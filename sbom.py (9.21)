# 현재 시스템에서 실행 중인 프로세스들의 상세 정보를 수집에 json파일 형태로 저장하는 프로그램
# 실행 중인 애플리케이션과 그 구성요소를 실시간으로 파악하여 기록하는 도구

import os
import psutil
import json
import subprocess
import hashlib
from datetime import datetime

#파일 해시(SHA256) 계산
def file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# <현재 실행 중인 프로세스 기록>
def system_sbom():
    processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'exe']):
        info = proc.info
        processes.append({
            "pid": info['pid'],
            "name": info['name'],
            "exe": info['exe']
        })
    return processes
# psutil 라이브러리를 사용해 현재 실행 중인 모든 프로세스의 PID, 이름, 실행 파일 경로를 가져옴
# 해당 정보를 리스트 형태로 반환

# <실행파일 정보 기록>
def executable_sbom(proc_info):
    exe_path = proc_info.get("exe")
    if not exe_path:
        return None
    data = {
        "name": proc_info["name"],
        "pid": proc_info["pid"],
        "path": exe_path,
        "hash": file_hash(exe_path),
        "dependencies": dependency_sbom(exe_path)
    }
    return data
# sysetem_sbom()에서 얻은 각 프로세스의 정보를 받아옴
# file_hash()함수를 호출해 해당 실행 파일의 해시값을 계산, 해당 해시는 파일의 고유 지문 역할
# dependency_sbom() 함수를 호출해 실행 파일이 의존하는 라이브러리 목록을 찾음

# <ldd 명령으로 실행파일이 의존하는 라이브러리 찾기>
def dependency_sbom(exe_path):
    deps = []
    try:
        output = subprocess.check_output(["ldd", exe_path], text=True)
        for line in output.splitlines():
            parts = line.strip().split("=>")
            if len(parts) == 2:
                lib_path = parts[1].strip().split(" ")[0]
                if os.path.exists(lib_path):
                    deps.append({
                        "lib": lib_path,
                        "hash": file_hash(lib_path)
                    })
    except Exception:
        pass
    return deps
# 

if __name__ == "__main__":
    sbom = {
        "timestamp": datetime.utcnow().isoformat(),
        "system": []
    }

    for proc in system_sbom():
        exe_sbom = executable_sbom(proc)
        if exe_sbom:
            sbom["system"].append(exe_sbom)


    with open("runtime-sbom.json", "w") as f:
        json.dump(sbom, f, indent=2)

    print("[완료] runtime-sbom.json 파일이 생성되었습니다!")
