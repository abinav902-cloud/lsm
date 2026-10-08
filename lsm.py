import subprocess
import sqlite3
import datetime
import re
result=subprocess.run(["ps","-ef"],
                      capture_output=True,
                      text=True
                      )
net_result=subprocess.run(["ss","-tulpn"],
                          capture_output=True,
                          text=True
                          )
all_net_process=[]
net_lines=net_result.stdout.splitlines()
for entry in net_lines:
    if "Netid" in entry:
        continue
    fields=entry.split()
    netid, state, recvq, sendq, local, peer, *process = fields
    if not process:
        net_pid=None
    else:
        raw_process=process[0]
        match=re.search(r"pid=(\d+)",raw_process)    
        if match :
            net_pid=match.group(1)
        else:
            net_pid=None    
    net_process={
        "netid":netid,
        "state":state,
        "recvq":recvq,
        "sendq":sendq,
        "local":local,
        "peer":peer,
        "process":process,
        "net_pid":net_pid

    }
    all_net_process.append(net_process)
    

all_process={}
conn=sqlite3.connect("lsm.db")
cursor=conn.cursor()
create_table_sql="""
CREATE TABLE IF NOT EXISTS processes(
    uid TEXT,
    pid TEXT,
    ppid TEXT,
    c TEXT,
    stime TEXT,
    tty TEXT,
    time TEXT,
    time_stamp TEXT,
    cmd TEXT

)"""
cursor.execute(create_table_sql)
current=str(datetime.datetime.now())
lines=result.stdout.splitlines()
for line in lines:
    if "PID" in line:
        continue
    parts=line.split()
    uid, pid, ppid, c, stime, tty, time, *cmd = parts
    process={
        "uid":uid,
        "pid":pid,
        "ppid":ppid,
        "c":c,
        "stime":stime,
        "tty":tty,
        "time":time,
        "cmd":" ".join(cmd)
    }
 
    all_process[pid]=process
    cursor.execute("INSERT INTO processes (uid, pid, ppid, c, stime, tty, time, time_stamp, cmd) VALUES (?,?,?,?,?,?,?,?,?)",
                   (uid, pid, ppid, c, stime, tty, time, current,process["cmd"]))
suspicious_pairs = [
    ("bash", "firefox"),
    ("bash", "chrome"),
    ("sh", "acrobat"),
]
findings=[]   
for pid in all_process: 
   
    try:
 
        parent_pid = all_process[pid]["ppid"]
        parent_process = all_process[parent_pid]
        parent_cmd=parent_process["cmd"]
        for suspicious_child,suspicious_parent in suspicious_pairs:
            if suspicious_child in all_process[pid]["cmd"] and suspicious_parent in parent_cmd:
                risk_score="Medium"
                connection=None
                for net_entry in all_net_process:
                    if net_entry["net_pid"]==pid:
                        risk_score="High"
                        connection=net_entry["local"]
                        print(f"  -> also has network activity: {net_entry['local']},{risk_score}")
                print(f"suspicious: {pid} is {suspicious_child}, spawned by {suspicious_parent},{risk_score}")   
                findings.append({
                    "pid":pid,
                    "child": suspicious_child ,
                    "parent":suspicious_parent,
                    "risk":risk_score,
                    "connection":connection




                })   
                 
       
    except KeyError:
        print(f"no parent found for {pid}")


for finding in findings:
    print(f"pid: {finding['pid']}, child: {finding['child']}, parent: {finding['parent']}, risk: {finding['risk']}")