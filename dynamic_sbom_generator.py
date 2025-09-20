# dynamic_sbom_generator.py

import os
import sys
import psutil
import json
from datetime import datetime
import pkg_resources

# CycloneDX 스키마의 기본 구조를 정의하는 템플릿 함수입니다.
# SBOM의 메타데이터와 전체 구조를 초기화합니다.
def create_cyclonedx_template(app_name="Dynamic SBOM Example"):
    """
    CycloneDX SBOM의 기본 템플릿을 생성합니다.
    Args:
        app_name (str): SBOM을 생성할 애플리케이션의 이름입니다.
    Returns:
        dict: CycloneDX SBOM 스키마 템플릿입니다.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{os.urandom(16).hex()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "User", "name": "Dynamic SBOM Generator", "version": "1.0"}],
            "component": {
                "name": app_name,
                "type": "application",
                "bom-ref": "pkg:generic/dynamic-app-example"
            }
        },
        "components": []
    }

# 실행 중인 Python 프로세스 정보와 로딩된 라이브러리 정보를 수집합니다.
# `sys.modules`를 사용해 현재 런타임에 로드된 패키지를 식별하고,
# `pkg_resources`를 통해 패키지 이름과 버전을 정확히 가져옵니다.
def collect_dynamic_components():
    """
    현재 런타임에 로드된 Python 패키지들을 수집하여 CycloneDX 컴포넌트 형식으로 반환합니다.
    Returns:
        list: CycloneDX 컴포넌트 목록입니다.
    """
    components = []
    # 이미 로드된 모듈 목록을 순회합니다.
    for name, module in sys.modules.items():
        try:
            # `pkg_resources`를 사용하여 패키지 이름과 버전을 정확하게 가져옵니다.
            dist = pkg_resources.get_distribution(name)
            
            # CycloneDX 포맷에 맞게 정보 구성
            component = {
                "bom-ref": f"pkg:pypi/{dist.project_name}@{dist.version}",
                "name": dist.project_name,
                "version": dist.version,
                "type": "library",
                "purl": f"pkg:pypi/{dist.project_name}@{dist.version}"
            }
            components.append(component)
        except (AttributeError, KeyError, pkg_resources.DistributionNotFound):
            # 모듈이 패키지가 아니거나, 배포 정보를 찾을 수 없는 경우 건너뜁니다.
            continue
            
    # 중복된 컴포넌트를 제거하여 정확한 목록을 만듭니다.
    unique_components = {comp['purl']: comp for comp in components}.values()
    
    return list(unique_components)

# 동적 SBOM을 생성하고 CycloneDX 포맷의 JSON 파일로 저장합니다.
def generate_dynamic_sbom():
    """
    동적 SBOM을 생성하고 'dynamic_sbom.json' 파일로 저장하는 메인 함수입니다.
    """
    # 템플릿을 사용하여 SBOM 객체를 초기화합니다.
    sbom = create_cyclonedx_template()
    
    # 런타임 컴포넌트 목록을 수집합니다.
    dynamic_components = collect_dynamic_components()
    
    # 수집된 컴포넌트를 SBOM에 추가합니다.
    sbom["components"].extend(dynamic_components)
    
    # JSON 파일로 저장
    output_file = "dynamic_sbom.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, ensure_ascii=False, indent=4)
        
    print(f"동적 SBOM이 '{output_file}' 파일로 성공적으로 생성되었습니다.")

# 스크립트 실행
if __name__ == "__main__":
    # 이 스크립트를 실행하면 현재 런타임에 로딩된 라이브러리 정보 기반의
    # 동적 SBOM을 생성합니다.
    generate_dynamic_sbom()
