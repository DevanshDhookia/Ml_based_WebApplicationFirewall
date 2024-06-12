import json
import re
import subprocess
import sys
import urllib.parse
import predict
import logging
#import post
#from confluent_kafka import Consumer, KafkaException

# We took input from kafka 

# This function is to extract all the components from the log_entry 
def parse_url_log(log_entry) :
    url_components = {}
    
    pattern = r'^(?P<IP_Address>\S+) - - \[(?P<Timestamp>[^\]]+)\] "(?P<HTTP_Method>[A-Z]+) (?P<Endpoint>\S+.*?) (?P<HTTP_Version>HTTP/\d\.\d)"'
    try:
        match = re.match(pattern, log_entry)
        if match:
            # If match found then we will store all the components in url_components and return them as dictionary.
            url_components = match.groupdict()
    except re.error as e:
        print(f"Regex error: {e}")
    
    return url_components

broker_address = '1.2.3.4:6565'
topic = 'access_logs'

conf = {
    'bootstrap.servers': broker_address,
    'group.id': 'python_consumer_group',
    'auto.offset.reset': 'earliest'
}

# consumer = Consumer(conf)
# consumer.subscribe([topic])

pattern = r'\"(?:GET|POST|PUT|DELETE|PATCH)\s(.*?)\sHTTP'

def ml_input(log_line):
        try :
        # while True:
            # msg = consumer.poll(1.0)
            # # This line polls for messages form a kafka consumer with a timeout of 1.0 second 

            # if msg is None:
            #     continue
            # if msg.error():
            #     if msg.error().code() == KafkaException:
            #         continue
            #     else:
            #         print(msg.error())
            #         break
            # print(log_line)
            # log_line = msg.value().decode('utf-8')
            # Decodes the value of the messages from bytes to a UTF-8 encoded string 
            # print(f"Received message: {msg.value().decode('utf-8')}")
            # filter using the http methods to extract the urls from the data.
            #print(log_line)
            # log_line='127.0.0.1 - - [16/May/2024 06:46:17] "GET /responsible-disclosure?https://www.iitk.ac.in/mwn/AIML/index.html&gad_source=1&gclid=CjwKCAjww_iwBhApEiwAuG6ccBC1JSfzdlpzJNtJO1an38cLqszdWnXDV6dW57HkLajPtvQ1qE7inhoCjiMQAvD_BwE HTTP/1.0"'            
            # log_line='127.0.0.1 - - [05/Jun/2024:06:13:57] "GET /responsible-disclosure?https://www.iitk.ac.in/mwn/AIML/index.html&gad_source=1&gclid=CjwKCAjww_iwBhApEiwAuG6ccBC1JSfzdlpzJNtJO1an38cLqszdWnXDV6dW57HkLajPtvQ1qE7inhoCjiMQAvD_BwE HTTP/1.0"'

            
            
            
            extracted_url = re.findall(pattern, log_line)
            #print("Extracted_url",extracted_url)
            # Extracted the urls form the log line using regex 

            if extracted_url:
                attack = {}
                # initialised attack dictionary 
                parsed_url = parse_url_log(log_line)
                #print("Parsed_url",parsed_url)
                if parsed_url:
                    decod_url = urllib.parse.unquote(extracted_url[0])

                    # Url encoding replaces certain characters in the URL with % sign followed by hexadecimal digits.
                    # urllib.parse.unquote reverses this this encoding.
                    # command = [sys.executable, "predict.py"]
                    # process = subprocess.run(command, input=decod_url, text=True, capture_output=True)
                    result=predict.process_input_url(decod_url)
                    output=json.loads(result)
                    # This line executes the command in a subprocess,passing the decoded URL and capturing the output 
                    # output = process.stdout.strip()
                    # output of the process is stored in output variable 
                    #print("Prediction:- ", output, " Parsed URL:- ", parsed_url)
                    if len(output)>2:
                        if 'IP_Address' in parsed_url:
                            attack["IP"] = parsed_url['IP_Address']
                        if 'Timestamp' in parsed_url:
                            attack["Timestamp"] = parsed_url['Timestamp']
                        if 'HTTP_Method' in parsed_url:
                            attack["HTTP_Method"] = parsed_url['HTTP_Method']
                        if 'Endpoint' in parsed_url:
                            attack["Endpoint"] = parsed_url['Endpoint']
                        # if 'Response_Code' in parsed_url:
                        #     attack["Response_Code"] = parsed_url['Response_Code']
                        # if 'User_Agent' in parsed_url:
                        #     attack["User_Agent"] = parsed_url['User_Agent']
                        
                        attack["Attack_Data"] = output
                        # x=json.loads(output)
                        # print(len(x))
                        json_string = json.dumps(attack)

                        return output
                    return output
                        # print(json_string)
                        #post.post_event(json.loads(json_string))
            else :
                return {}

        except KeyboardInterrupt:
            pass