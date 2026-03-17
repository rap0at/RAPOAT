<img src="https://capsule-render.vercel.app/api?type=waving&color=auto&height=200&section=header&text=RAP0AT&fontSize=90" />

## NOTICE
>A tool that automatically performs all basic web hacking attacks.

## Features

- Main Page
<img width="601" height="360" alt="main" src="https://github.com/user-attachments/assets/6146b735-d1bb-4a69-873e-c387bb846eba" />


- WEB MODE
<img width="965" height="522" alt="web1" src="https://github.com/user-attachments/assets/7a158cab-0053-41b1-a310-dd26df2c4cae" />
<img width="1212" height="798" alt="web2" src="https://github.com/user-attachments/assets/3649ea16-99af-43e8-8d16-3d6b3f23d9b0" />


- TERMINAL MODE
<img width="504" height="349" alt="terminal" src="https://github.com/user-attachments/assets/45f81290-bc1f-4222-a5d5-328793dff623" />


- AI MODE
<img width="651" height="404" alt="ai" src="https://github.com/user-attachments/assets/24bc1482-6dd4-4d41-b696-39f0c03816e7" />


## Gemini or Claude API key require
```sh
https://ai.google.dev/gemini-api/docs/api-key
                    OR
https://platform.claude.com/settings/keys
```

## Installation
```sh
sudo apt-get update && sudo apt-get install -y nmap nikto nuclei smbclient snmp dnsutils python3-pip python3-venv
git clone https://github.com/rap0at/RAPOAT.git
cd RAPOAT
chmod 777 *
python3 -m venv venv
source /venv/bin/activate
pip3 install -r requirements.txt
playwright install
python3 rapoat.py
```

## In case of lxml html err
```sh
pip3 install 'lxml[html_clean]'
```

## In case of gemini err
```sh
[ERROR] Failed to configure Gemini API: module 'google.genai' has no attribute 'configure'
                  DO THIS
* pip install --upgrade google-generativeai
                    OR
* pip uninstall google-generativeai -y
* pip install google-genai
```

## API Key Options
```sh
If you enter only one of the Gemini and Claud api keys, the tool will operate normally.
```

## Adjust the overall speed of the tool
```sh
You can adjust the overall attack speed of the tool by adjusting the thread value in the config.ini file that is automatically generated in ai mode.
```
<img width="165" height="158" alt="thread" src="https://github.com/user-attachments/assets/66d15fa4-d431-4be2-abf3-8b1a9e15f6e5" />
