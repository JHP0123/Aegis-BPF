#!/bin/bash

echo "================================================="
echo " Aegis-NG (Current Version) Automated Test Script"
echo "================================================="

# 1. 테스트용 가상 서버(Alpine) 준비
docker rm -f aegis-target 2>/dev/null
echo "[*] 테스트용 가상 망(컨테이너)을 생성합니다..."
# HTTP(Nginx) 대신 연결을 끊지 않는 단순 대기 상태의 컨테이너 실행
docker run -d --name aegis-target alpine sleep 3600
TARGET_IP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' aegis-target)

echo "[*] 가상 서버 IP: $TARGET_IP"
echo ""
echo -e "\033[1;31m[매우 중요] 지금 다른 터미널 창에서 실행 중인 엔진을 껐다가 다시 켜주세요!\033[0m"
echo -e "1. 기존 엔진 터미널에서 \033[1;33mCtrl+C\033[0m 를 눌러 종료합니다."
echo -e "2. \033[1;32msudo ./aegis docker0\033[0m (또는 controller) 명령어로 다시 실행합니다."
echo ""
read -p "엔진이 새롭게 'Monitoring...' 상태가 되었다면 [Enter]를 누르세요..."

echo ""
echo "================================================="
echo "▶ Test 1: 일반 대용량 유출 탐지 (TCP)"
echo "================================================="
echo "- 목적: TCP 연결이 너무 빨리 닫히는(tcp_close) 것을 막기 위해"
echo "- 전략: 2GB의 막대한 데이터를 전송하여 최소 4~5초 이상 소켓을 유지시킵니다."
echo "- 결과: 엔진 터미널에 [BLOCK] Bulk Exfiltration이 떠야 합니다."
# 컨테이너 내부에 수신 포트 오픈
docker exec -d aegis-target nc -l -p 8080
# 2GB 전송 (엔진이 1초 타이머를 돌릴 충분한 시간을 줌)
dd if=/dev/zero bs=1M count=2000 2>/dev/null | nc -w 5 $TARGET_IP 8080
echo "✔ [Test 1 완료] 엔진 로그를 확인하세요."
echo ""
read -p "다음 테스트로 넘어가려면 [Enter]를 누르세요..."

echo ""
echo "================================================="
echo "▶ Test 2: DNS 터널링 탐지 (UDP 53) - Python 스트리밍"
echo "================================================="
echo "- 목적: 리눅스 파이프(|)의 버퍼링 엇박자 문제 회피"
echo "- 전략: Python으로 0.1초마다 8KB씩 3초간 정밀하게 UDP 패킷을 전송합니다."
echo "- 결과: 1~2초 뒤 [BLOCK] DNS Tunneling Detected가 떠야 합니다."
python3 -c "import socket, time; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); [(s.sendto(b'X'*1024, ('$TARGET_IP', 53)), time.sleep(0.02)) for _ in range(150)]"
echo "✔ [Test 2 완료] 엔진 로그를 확인하세요."
echo ""
read -p "다음 테스트로 넘어가려면 [Enter]를 누르세요..."

echo ""
echo "================================================="
echo "▶ Test 3: C2 비코닝 탐지 (UDP 9999)"
echo "================================================="
echo "- 전략: tcp_close의 간섭을 피해 UDP 패킷을 정확히 3초 간격으로 5번 전송합니다."
echo "- 결과: 15초 뒤 [BLOCK] C2 Beaconing Detected (CV < 0.10)가 떠야 합니다."
for i in {1..6}; do
    echo "beacon_ping" | nc -u -w 1 $TARGET_IP 9999
    echo "  - $i 번째 비코닝 패킷 전송 완료"
    sleep 3.1
done
echo "✔ [Test 3 완료] 엔진 로그를 확인하세요."
echo ""

# 환경 정리
echo "[*] 테스트 컨테이너를 삭제하고 종료합니다."
docker rm -f aegis-target >/dev/null
echo "수고하셨습니다!"
