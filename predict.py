import json
import sys
import urllib.parse
import pickle
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.ensemble import RandomForestClassifier

data = []
attack_data = {}

# Function to decode URL multiple times
def decode_url_multiple_times(url, times):
    decoded_url = url
    for _ in range(times):
        decoded_url = urllib.parse.unquote(decoded_url)
    return decoded_url

# Function to process a specific type of attack
def process_attack(decoded_url, symbols, model_filename):
    features = [int(symbol in decoded_url) for symbol in symbols]

    with open(model_filename, 'rb') as model_file:
        trained_model = pickle.load(model_file)

    trained_model.feature_names_in_ = None

    preprocessor = ColumnTransformer(transformers=[('features', FunctionTransformer(lambda x: x), symbols)])
    model = Pipeline([('preprocessor', preprocessor), ('classifier', trained_model)])

    y_pred_prob = trained_model.predict_proba([features])
    predicted_proba = y_pred_prob[0]
    class_names = {0: 1, 1: 0}                # 0: 'Malicious', 1: 'Benign'
    max_prob_index = predicted_proba.argmax()

    predicted_label = class_names[max_prob_index]
    confidence_score = predicted_proba[max_prob_index]

    return predicted_label, confidence_score

def generate_attack_data(attack_type, predicted_label, confidence_score):
    return {"Attack:": attack_type, "Prediction:": predicted_label, "Confidence Score:": confidence_score}

def process_input_url(input_url):

    decoded_url_1 = decode_url_multiple_times(input_url, 1)
    decoded_url_2 = decode_url_multiple_times(input_url, 2)
    decoded_url_4 = decode_url_multiple_times(input_url, 4)

    # CRLFi Attack
    symbols_CRLFi = ['%0A', '%0D', '%0D%0A', 'SET', 'COOKIE', ':', '+', 'TAMPER']
    predicted_label_CRLFi, confidence_score_CRLFi = process_attack(decoded_url_1, symbols_CRLFi, 'trainmodelCRLFi.sav')
    if predicted_label_CRLFi:
        attack_data["CRLFi"] = confidence_score_CRLFi
    # SQLi Attack
    symbols_SQLi = ['-', '#', '%', '+', "'", ';', '#', '=', '[', ']', '(', ')', '&&', '*', 'True', ',', '-', '<', '>', ' ', '.', '|', '"', '<<', '<=', '>=', '&&', '||', ':', '!=', 'count', 'into', '&&', '||', '!', 'null', 'select', 'union', 'insert', 'update', 'delete', 'drop', 'replace', 'all', 'any', 'from', 'user', 'where', 'storedprocedure', 'extendedprocedure', 'like', 'execute', 'administrator', 'table', 'sleep', 'commit', '()', 'between']
    predicted_label_SQLi, confidence_score_SQLi = process_attack(decoded_url_2, symbols_SQLi, 'trainmodelSQLi.sav')
    if predicted_label_SQLi:
        attack_data["SQLi"] = confidence_score_SQLi

    # XSS Attack
    symbols_XSS = ['&', '%', '/', '\\', '+', "'", ' ?', ' !', ';', '#', '=', '[', ']', '$',  '(', ')', '∧', '*', ',', '-', '<', '>', '@', ':', '{', '}', '.', '|','"', '<>', '==','&#', 'document','window','iframe','div','img','location', 'this','var', 'onload','createElement','search', '<script', 'src','href','cookie', 'eval()', 'http', '.js']
    predicted_label_XSS, confidence_score_XSS = process_attack(decoded_url_2, symbols_XSS, 'trainmodelXSSS.sav')
    if predicted_label_XSS:
        attack_data["XSS"] = confidence_score_XSS

    # Path Traversal Attack
    symbols_PathTraversal = ['../', '..\\', 'etc', 'passwd', '\\.', '\\/', './', '/', ':', '//', ':/','system', 'ini', '..', 'exec', ':\\', '%00', '.bat', 'file', 'windows', 'boot', 'winnt', '.conf', 'access', 'log', ',,']
    predicted_label_PathTraversal, confidence_score_PathTraversal = process_attack(decoded_url_4, symbols_PathTraversal, 'trainmodelPathTraversal.sav')
    if predicted_label_PathTraversal:
        attack_data["PathTraversal"] = confidence_score_PathTraversal

    # LDAP Attack
    symbols_LDAP = ['\\', '*', ',', '(',')', '/', '+', '<','>', ';', '"', '&','|', '&(', '|(', ')(', ',', '! ','=', '&)', ' ', '*', '))', '&(',')+ ', ')= ', 'Common Name','Surname', '=*', '|(','Mail', 'Object Class', 'Name']
    predicted_label_LDAP, confidence_score_LDAP = process_attack(decoded_url_1, symbols_LDAP, 'trainmodelLDAP.sav')
    if predicted_label_LDAP:
        attack_data["LDAP"] = confidence_score_LDAP

    # XPath Attack
    symbols_XPath = ['/*', '%', '+', '0 ', ';', '#', '=', '[', ']', '(', ')', '∧', '*', '()', '//', ',', '-', '<', '>', '.', '|', '"', '<>', '<=', '>=', '&&', '||', '::', '((', '< --', ' ', 'or', 'count', 'path/', 'and', 'not', 'text()', 'child', 'position()', 'node()', 'name', 'user', 'comment']
    predicted_label_XPath, confidence_score_XPath = process_attack(decoded_url_1, symbols_XPath, 'trainmodelXPath.sav')
    if predicted_label_XPath:
        attack_data["XPath"] = confidence_score_XPath

    # SSI Attack
    symbols_SSI = ['Startofcomment', 'Endofcomment', 'Hash', 'Plus', 'Comma', 'Doublequotationmark', 'Etcdirectory', 'Passwdfile', 'Directory', 'Exec', 'CMD', 'FromHost', 'Email', 'ODBC', 'Include', 'Virtual', 'Bin', 'ToAddress', 'Message', 'ReplyTo', 'Sender', 'Echo', 'HTTPD', 'AccessLog', 'Var', 'Connect', 'DateGMT', 'Statement', 'LogDirectory', 'MailDirectory', 'Mail','ID', 'PlusID', 'BatchFile', 'LS', 'HomeDirectory', 'WinNTDirectory', 'SystemINI', 'Conf', 'MinusL', 'Windows', 'COM', 'Drive']
    predicted_label_SSI, confidence_score_SSI = process_attack(decoded_url_1, symbols_SSI, 'trainmodelSSI.sav')
    if predicted_label_SSI:
        attack_data["SSI"] = confidence_score_SSI

    # OSCommand Attack
    symbols_OSCommand = ['../', '..\\', 'etc', 'passwd', '\\.', '\\/', './', ':', ':/', '.', 'system32', 'display', '.exe', 'cmd', 'dir', ';', 'tmp/', 'etc/passwd', 'wget', 'cat', 'ping', 'bash', 'ftp', '|', '..', 'exec', ':\\', '.bat', 'file', 'script', 'rm', 'c:', 'winnt', 'access', 'log', "''", 'www.', 'http', ' ', 'bin/', 'telnet',  'echo', 'root', '-aux', 'shell', 'uname', 'IP']
    predicted_label_OSCommand, confidence_score_OSCommand = process_attack(decoded_url_2, symbols_OSCommand, 'trainmodelOSCommand.sav')
    if predicted_label_OSCommand:
        attack_data["OSCommand"] = confidence_score_OSCommand

    # Anomaly Attack
    # symbols_Anomaly = [ '&', '%', '/', '\\', '+', "'", ' ?',
    #                  ' !', ';', '#', '=', '[', ']', '$', 
    #                 '(',  ')', '∧', '*',  ',', '-', '<', 
    #                 '>', '@', ':', '{', '}', '.', '|', 
    #                 '"', '<>', '==', '&#', 'document', 'window', 'iframe', 
    #                 'div', 'img', 'location', 'this', 'var', 'onload', 
    #                 'createElement', 'search', '<script', 'src', 'href', 'cookie', 
    #                 'eval()', 'http', '.js','-', '#', '%', '+', "'", ';', '#',
    #                 '=', '[', ']', '(', ')', '&&', '*', 
    #                 'True', ',', '-', '<', '>', ' ', '.', 
    #                 '|', '"', '<<', '<=', '>=', '&&', '||', 
    #                 ':', '!=', 'count', 'into', '&&', '||', '!', 
    #                 'null', 'select', 'union', 'insert', 'update', 'delete', 
    #                 'drop', 'replace', 'all', 'any', 'from', 'user', 
    #                 'where', 'storedprocedure', 'extendedprocedure', 'like', 'execute',
    #                 'administrator','table', 'sleep', 'commit', '()', 'between','../', '..//', 'etc', 'passwd', '\\.',
    #                 '\\\\', '.', '/', ':', '//', ':\\', 
    #                 'system', '.ini', '..', 'exec', ':\\', '%00',
    #                 '.bat', 'file','windows', 'boot', 'winnt', '.conf',
    #                 'access','log', ',, ','\\', '*', ',', '(', 
    #                 ')', '/', '+', '<','>', ';', 
    #                 '"', '&', 
    #                 '|', '&(', '|(', ')(', ',', '! ',
    #                 '=', '&)', ' ', '*', '))', '&(',
    #                 ')+ ', ')= ', 'Common Name', 'Surname', '=*', '|(','Mail', 'Object Class', 'Name','/*', '%', '+', '0 ', ';', '#', '=', '[', ']', '(', ')', '&&', '*', '()', '// ', ',', '-', '<', '>', '.', '|', '"', '<>', '<= ', '>= ', '&&', '||', '::', '((', '<-', ' ', '||', 'count', '/', '&&', '!','text()', 'child', 'position()', 'node()', 'Name', 'User','Comment','<!--', '-->', '#', '+', ',', '"',
    #                 '/etc', '/passwd', '/directory', 'exec', 'CMD',
    #                 'FromHost', 'Email', 'ODBC', 'Include', 'Virtual',
    #                 '/bin', 'ToAddress', 'Message', 'ReplyTo', 'Sender',
    #                 'Echo', 'HTTPD', 'AccessLog', 'Var', 'Connect',
    #                 'DateGMT', 'Statement', 'LogDirectory', 'MailDirectory',
    #                 'Mail', 'ID', '+ID', '.bat', 'ls',
    #                 'HomeDirectory', 'WinNTDirectory', 'System.ini', '.conf',
    #                 '-l', 'Windows', 'COM', 'Drive','../', '..\\', 'etc', 'passwd', '\\.', '\\/',
    #                 './', ':', ':/', '.', 'system32', 'display', 
    #                 '.exe', 'cmd', 'dir', ';', 'tmp/', 'etc/passwd', 
    #                 'wget', 'cat', 'ping', 'bash', 'ftp', '|',
    #                 '..', 'exec', ':\\', '.bat', 'file', 'script', 
    #                 'rm', 'c:', 'winnt', 'access', 'log', "''’'", 
    #                 'www.', 'http', ' ', 'bin/', 'telnet', 
    #                 'echo', 'root', '-aux', 'shell', 'uname', 'IP','%0A', '%0D', '%0D%0A',
    #                 'SET', 'COOKIE', ':',
    #                 '+', 'TAMPER']
    # predicted_label_Anomaly, confidence_score_Anomaly = process_attack(decoded_url_1, symbols_Anomaly, 'trainmodelanomaly.sav')
    # if predicted_label_Anomaly:
    #     attack_data["Anomaly"] = confidence_score_Anomaly
    
    json_string = json.dumps(attack_data)
    #print("JSON_OUTPUT_STRING :",json_string)
    return json.dumps(json_string)
    # print(json_string)

if __name__ == "__main__":
    input_url = sys.stdin.readline().strip()
    process_input_url(input_url)

