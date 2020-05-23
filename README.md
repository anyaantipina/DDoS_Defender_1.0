# DDoS_Defender_1.0
Для установки приложения DDoS_Defender на контроллер RUNOS 2.0 необходимо:
1.	Перейти в директорию с приложениями для контроллера:
cd /runos/src/apps
2.	Загрузить репозиторий с исходными данными:
git clone https://github.com/anyaantipina/DDoS_Defender_1.0
3.	Если на контроллере еще не установлены приложения L2LearningSwitch, HostManager и DHCP сервер, загрузить репозитории с их исходными данными:
git clone https://github.com/ARCCN/l2-learning-switch.git
git clone https://github.com/ARCCN/host-manager.git
Исходные данные DHCP сервера на момент написания данной работы не находятся в открытом доступе. Чтобы получить исходные данные версии приложения DHCP сервера, совместимой с DDoS_Defender, необходимо отправить запрос на почту anya_antipina@lvk.cs.msu.su. 
4.	Заменить файл l2-learning-switch/src/L2LearningSwitch.сс на ddos-defender/extra/L2LearningSwitch.cc, так как для корректной работы приложения DDoS_Defender в данный файл были внесены изменения:
rm l2-learning-switch/src/L2LearningSwitch.сс
cp ddos-defender/extra/L2LearningSwitch.cc \
l2-learning-switch/src/L2LearningSwitch.сс
5.	Задать настраиваемые параметры для приложения DDoS_Defender в файле runos/src/appc/ddos-defender/settings.json и для приложения DhcpServer в файле  runos/src/appc/dhcp-server/settings.json.
6.	Запустить nix-shell в директории runos:
cd ../../..
nix-shell
7.	Cобрать контроллер:
mkdir build
cd build
cmake ..
make
cd ..
8.	Запустить контроллер:
./build/runos
