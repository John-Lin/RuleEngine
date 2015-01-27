import os
import sys
import shutil
import time
import datetime
from bottle import route, request, static_file, run
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
from malware.core.engine import RuleEngineOnline
from bottle import error


def gen_rule(path):
    rules = list()
    r = RuleEngineOnline(path)
    r.http_rule_generate()
    r.dns_rule_generate()

    sid = 0
    for ruleobj in r.rules:
        sid += 1
        ruleobj.sid = sid
        rules.append(str(ruleobj))

    rules = list(set(rules))
    t = time.time()
    t_stamp = datetime.datetime.fromtimestamp(t).strftime('%Y-%m-%d %H-%M-%S')
    fp = open('history.rules', 'a')
    fp.write(t_stamp + '\n')
    for r in rules:
        # print r
        fp.write(r + '\n')
    fp.close()

    view_rules = "<p>".join(rules)
    return view_rules


@route('/')
def root():
    return static_file('index.html', root='.')


@error(404)
def error404(error):
    return '404 not found'


@error(500)
def error500(error):
    return '500 internal server error'


@route('/upload', method='POST')
def do_upload():
    # category = request.forms.get('category')
    t = time.time()
    t_stamp = datetime.datetime.fromtimestamp(t).strftime('%Y_%m_%d_%H_%M_%S')
    upload = request.files.get('upload')

    if upload is None:
        return 'Please select a PCAP file'
    name, ext = os.path.splitext(upload.filename)

    if ext not in ('.pcap'):
        return "File extension not allowed."

    save_path = "./upload/{category}".format(category=t_stamp)

    if not os.path.exists(save_path):
        os.makedirs(save_path)
    else:
        shutil.rmtree(save_path)
        os.makedirs(save_path)

    file_path = "{path}/{file}".format(path=save_path, file=upload.filename)
    upload.save(file_path)

    view_rules = gen_rule(save_path)

    if view_rules:
        return "Snort rules have been generated: <p>{r}".format(r=view_rules)
        # return "File successfully saved to '{0}'.".format(save_path)
    else:
        return "Can not generate any rule."


if __name__ == '__main__':
    run(host='localhost', port=8080)
