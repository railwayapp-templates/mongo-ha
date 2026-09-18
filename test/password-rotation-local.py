#!/usr/bin/env python3
"""Real three-member MongoDB/wrapper rotation. Requires pymongo, MONGOD and MONGO_WRAPPER."""
import base64, hashlib, json, os, pathlib, signal, subprocess, tempfile, time, urllib.request
from pymongo import MongoClient, ReadPreference
OLD, NEW = 'rotation-old-local', 'rotation-new-local'
BASE = int(os.environ.get('ROTATION_TEST_PORT', '27370'))
MONGOD = os.environ['MONGOD']
WRAPPER = os.environ['MONGO_WRAPPER']
processes=[]

def client(i, password=None):
    opts=dict(directConnection=True,serverSelectionTimeoutMS=1500,connectTimeoutMS=1500,socketTimeoutMS=3000)
    if password: opts.update(username='root',password=password,authSource='admin')
    return MongoClient('127.0.0.1',BASE+i,**opts)

def wait(fn, seconds=120):
    until=time.monotonic()+seconds; error=None
    while time.monotonic()<until:
        try:
            if any(p.poll() is not None for p, _, _ in processes): raise SystemExit('test child exited before readiness')
            if fn(): return
        except Exception as e: error=e
        time.sleep(.3)
    raise AssertionError(f'condition timed out: {error}')

def healthy(password):
    for i in range(3):
        with client(i,password) as c:
            status=c.admin.command('replSetGetStatus')
            if len(status['members']) != 3 or any(m['health']!=1 or m['state'] not in [1,2] for m in status['members']): return False
    return True

def primary(password):
    for i in range(3):
        with client(i,password) as c:
            if c.admin.command('hello').get('isWritablePrimary'): return i
    raise RuntimeError('no primary')

def rotate(i, operation, target=NEW, previous=OLD):
    until=time.monotonic()+150; last=None
    while time.monotonic()<until:
        for password in [previous,target]:
            req=urllib.request.Request(f'http://127.0.0.1:{BASE+20+i}/credentials/rotate',data=json.dumps(dict(operation=operation,newPassword=target,currentPassword=previous)).encode(),headers={'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode(f'railway:{password}'.encode()).decode()})
            try:
                with urllib.request.urlopen(req,timeout=40) as r: return json.load(r)
            except Exception as error: last=error
        time.sleep(.5)
    raise RuntimeError(f'{operation} node {i}: {last}')

def rotation(target, previous):
    for i in range(3): rotate(i,'prepare',target,previous)
    rotate(primary(previous),'database',target,previous)
    for i in range(3): rotate(i,'member',target,previous)
    for operation in ['key_prepare','key_commit']:
        leader=primary(target)
        order=[i for i in range(3) if i!=leader]+[leader]
        for i in order:
            print(operation,i,flush=True)
            rotate(i,operation,target,previous)
            # Other members can retain the old heartbeat view briefly. The
            # quorum must remain available while that view converges.
            for node in range(3):
                with client(node,target) as c:
                    status=c.admin.command('replSetGetStatus')
                    assert sum(m['health']==1 and m['state'] in [1,2] for m in status['members']) >= 2
            wait(lambda: healthy(target))
            # A lost response must not initiate another restart.
            rotate(i,operation,target,previous)
    for i in range(3): rotate(i,'verify',target,previous)

with tempfile.TemporaryDirectory(prefix='mongo-rotation-') as temp:
    root=pathlib.Path(temp); key=base64.b64encode(hashlib.sha256(OLD.encode()).digest()).decode()
    entry=root/'docker-entrypoint.sh'; entry.write_text('#!/usr/bin/env python3\nimport os,shutil,sys\nargs=[]\nfor arg in sys.argv[1:]:\n args.extend(["--bind_ip","127.0.0.1"] if arg=="--bind_ip_all" else [arg])\nos.execv(shutil.which(args[0]),args)\n'); entry.chmod(0o755)
    try:
        for i in range(3):
            d=root/str(i);d.mkdir(); (d/'keyfile').write_text(key);(d/'keyfile').chmod(0o400)
            log=open(d/'mongod.log','wb')
            p=subprocess.Popen([MONGOD,'--port',str(BASE+i),'--bind_ip','127.0.0.1','--dbpath',str(d),'--replSet','rotation','--keyFile',str(d/'keyfile'),'--wiredTigerCacheSizeGB','0.25'],stdout=log,stderr=log,start_new_session=True)
            processes.append((p,log,d))
        wait(lambda: client(0).admin.command('ping').get('ok'))
        with client(0) as c: c.admin.command('replSetInitiate',{'_id':'rotation','members':[{'_id':i,'host':f'127.0.0.1:{BASE+i}'} for i in range(3)]})
        wait(lambda: primary(None)>=0)
        with client(primary(None)) as c: c.admin.command('createUser','root',pwd=OLD,roles=[{'role':'root','db':'admin'}],writeConcern={'w':'majority'})
        wait(lambda: healthy(OLD))
        for p,log,d in processes: p.terminate()
        for p,log,d in processes: p.wait(timeout=45);log.close()
        processes=[]
        for i in range(3):
            d=root/str(i)
            (d/'.railway-mongo-auth-pin').write_text(json.dumps({'password':OLD,'keyfile':key}));(d/'.railway-mongo-auth-pin').chmod(0o600)
            env={**os.environ,'PATH':str(root)+':'+str(pathlib.Path(MONGOD).parent)+':'+os.environ['PATH'],'MONGO_INITDB_ROOT_USERNAME':'root','MONGO_INITDB_ROOT_PASSWORD':OLD,'MONGO_PORT':str(BASE+i),'HEALTH_PORT':str(BASE+20+i),'RS_SEEDS':','.join(f'127.0.0.1:{BASE+j}' for j in range(3)),'RS_NAME':'rotation','RS_KEY':OLD,'RS_KEYFILE_PATH':str(d/'keyfile'),'DATA_DIR':str(d),'RAILWAY_PRIVATE_DOMAIN':'127.0.0.1','RUST_LOG':'warn'}
            log=open(d/'wrapper.log','wb')
            p=subprocess.Popen([WRAPPER,'--wiredTigerCacheSizeGB','0.25'],env=env,stdout=log,stderr=log,start_new_session=True)
            processes.append((p,log,d))
        wait(lambda: healthy(OLD))
        for i in range(3): rotate(i,'preflight',OLD,OLD)
        with client(primary(OLD),OLD) as c: c.rotation.proof.insert_one({'_id':'retained'})
        rotation(NEW,OLD)
        for i in range(3):
            with client(i,NEW) as c: assert c.rotation.get_collection('proof',read_preference=ReadPreference.SECONDARY_PREFERRED).find_one({'_id':'retained'})
        rotation(OLD,NEW)
        print('PASS: root and keyfiles rotated through two rolling passes, retried, and compensated; quorum and data retained',flush=True)
    except BaseException:
        for p,log,d in processes:
            log.flush(); print('node',d.name,(d/'wrapper.log').read_text()[-5000:] if (d/'wrapper.log').exists() else (d/'mongod.log').read_text()[-5000:])
        raise
    finally:
        for p,log,d in processes:
            if p.poll() is None:
                try: os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError: pass
            p.wait();log.close()
