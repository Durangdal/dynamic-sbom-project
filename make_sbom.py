# 이 스크립트는 eBPF 기반 모니터링과 애플리케이션 계측을 결합하여
# 하이브리드 런타임 SBOM을 생성합니다.
# eBPF를 통해 시스템 전반의 컴포넌트를 수집하고, 애플리케이션 계측으로
# Python 패키지 정보를 정확하게 파악합니다.

import os
import sys
import json
from datetime import datetime
import pkg_resources
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5

# 참고: 실제 eBPF 프로그램 연동을 위해서는 bcc, libbpf-python과 같은 라이브러리가 필요합니다.
# 이 코드는 개념을 설명하기 위해 'simulated_ebpf_data'를 사용합니다.

def create_cyclonedx_template(app_name="Hybrid Runtime SBOM"):
    """
    CycloneDX SBOM의 기본 템플릿을 생성합니다.
    Args:
        app_name (str): SBOM을 생성할 애플리케이션의 이름입니다.
    Returns:
        Bom: 초기화된 CycloneDX Bom 객체입니다.
    """
    bom = Bom()
    bom.metadata.component = Component(
        name=app_name,
        type=ComponentType.APPLICATION,
        bom_ref=f"pkg:generic/{app_name.lower().replace(' ', '-')}"
    )
    bom.metadata.tools.add(Component(name="Hybrid SBOM Generator", vendor="User", version="1.0"))
    return bom

def get_application_components():
    """
    현재 런타임에 로드된 Python 패키지들을 수집하여 CycloneDX 컴포넌트 형식으로 반환합니다.
    'sys.modules'와 'pkg_resources'를 활용하여 정확한 정보를 얻습니다.
    Returns:
        dict: PURL을 키로 하는 컴포넌트 딕셔너리입니다.
    """
    components = {}
    for name, module in sys.modules.items():
        try:
            dist = pkg_resources.get_distribution(name)
            purl = f"pkg:pypi/{dist.project_name}@{dist.version}"
            
            # 중복 방지를 위해 PURL을 키로 사용
            if purl not in components:
                component = Component(
                    name=dist.project_name,
                    version=dist.version,
                    purl=purl
                )
                component.type = ComponentType.LIBRARY
                components[purl] = component
        except (AttributeError, KeyError, pkg_resources.DistributionNotFound):
            continue
            
    return components

def get_ebpf_components():
    """
    (시뮬레이션) eBPF 프로그램을 통해 수집된 시스템 레벨의 동적 컴포넌트들을 반환합니다.
    실제 구현에서는 이 함수가 eBPF 맵을 읽어 데이터를 가져옵니다.
    
    Returns:
        dict: PURL 또는 고유 식별자를 키로 하는 컴포넌트 딕셔너리입니다.
    """
    # eBPF 프로그램 로직 (개념 설명)
    # 1. BPF 프로그램 작성 (C/Rust) 및 컴파일: execve(), openat() 등 시스템 호출에 훅을 걸어
    #    프로세스 실행 및 동적 라이브러리(.so) 로드 이벤트를 감지합니다.
    # 2. BPF 맵 정의: 커널에서 사용자 공간으로 데이터를 전달하기 위한 맵을 정의합니다.
    # 3. 사용자 공간 로직 (Python): bcc 라이브러리 등을 사용해 BPF 프로그램을 커널에 로드하고
    #    주기적으로 맵에서 데이터를 읽어옵니다.
    
    print("[eBPF] eBPF 맵에서 시스템 컴포넌트 데이터를 수집하는 중... (시뮬레이션)")
    
    # 예시 데이터: 시스템에서 동적으로 로드된 라이브러리 목록
    simulated_ebpf_data = [
        {"name": "libssl", "version": "1.1.1", "path": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"},
        {"name": "libc", "version": "2.31", "path": "/lib/x86_64-linux-gnu/libc.so.6"}
    ]
    
    components = {}
    for data in simulated_ebpf_data:
        purl = f"pkg:generic/{data['name']}@{data['version']}"
        component = Component(
            name=data['name'],
            version=data['version'],
            purl=purl
        )
        component.type = ComponentType.LIBRARY
        component.description = f"Path: {data['path']}"
        components[purl] = component
        
    return components

def generate_hybrid_sbom():
    """
    하이브리드 런타임 SBOM을 생성하고 'hybrid_sbom.json' 파일로 저장하는 메인 함수입니다.
    """
    # 1. 애플리케이션 계측을 통해 Python 패키지 정보 수집
    print("1. Python 애플리케이션 컴포넌트 수집 중...")
    app_components = get_application_components()
    
    # 2. eBPF를 통해 시스템 레벨 컴포넌트 수집 (시뮬레이션)
    print("2. eBPF 기반 시스템 컴포넌트 수집 중...")
    ebpf_components = get_ebpf_components()
    
    # 3. 두 컴포넌트 목록 병합 (중복 제거)
    print("3. 컴포넌트 목록 병합 및 중복 제거 중...")
    all_components = app_components
    for purl, component in ebpf_components.items():
        if purl not in all_components:
            all_components[purl] = component

    # 4. CycloneDX BOM 생성
    print("4. CycloneDX BOM 생성 중...")
    bom = create_cyclonedx_template()
    for component in all_components.values():
        bom.components.add(component)

    # 5. JSON 파일로 저장
    print("5. JSON 파일로 저장 중...")
    outputter = JsonV1Dot5(bom)
    json_string = outputter.output_as_string()
    
    output_file = "hybrid_sbom.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(json_string)
        
    print(f"\n[완료] 하이브리드 SBOM이 '{output_file}' 파일로 성공적으로 생성되었습니다!")

# 스크립트 실행
if __name__ == "__main__":
    generate_hybrid_sbom()
