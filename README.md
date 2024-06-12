
# Web Application Firewall 

A WAF or web application firewall helps protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet. It typically protects web applications from attacks such as cross-site forgery, cross-site-scripting (XSS), file inclusion, and SQL injection, among others.

# About

Our web application firewall is powered by an advanced machine learning (ML) model, developed based on the [Research paper](https://link.springer.com/chapter/10.1007/978-3-030-35869-3_10). This model enables the WAF to identify and mitigate sophisticated threats effectively, ensuring robust protection for your web applications.


# Overview

Our WAF operates using a reverse proxy server. When an end user sends a request to the server, it first passes through the ML model. If the request is deemed safe, it is forwarded to the web server; otherwise, it returns an error response.




## Installation

Step 1 : Configure the website using any server on the private network.

Step 2 : Download WAF to your system  
```bash
  npm install my-project
  cd /path/to/WAF
```
Step 3 : Download the requirements

```bash
    sudo apt install python3
    sudo apt install python3-pip
    pip install scikit-learn==1.3.2
```
Step 4 : Change the config.json file 
```bash
    cd /path/to/WAF
    sudo nano config.json
```
Step 5 : Make logs directory to save logs 
```bash 
    sudo mkdir logs
```

Make sure to fill all the details appropiately and save the file

Step 6 : Start your apache server, where website was hosted 

Step 7 : Start your reverse proxy server
```bash
    sudo python3 newproxy.server
```

## Logging

Combined logs from the reverse proxy server will be saved in csv file in logs directory of WAF folder.
```bash
    cd /path/to/WAF/logs
    sudo nano proxy_logs_<YYYY-MM-DD>.csv
```
