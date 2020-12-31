# HeadersAreHard  
  
Headers are indeed hard (apparently). As a pentester, I check these ALL the time. And for reasons unknown, pentesters love to write pages and pages in reports about headers... or the lack of.  
  
These probably aren't as handy with bug bounties, but knowing how a user's browser may react based on the packet it receives might help identify impact or future attack steps. Regardless, here we are :)  
  
### Installation  
  
```
go get github.com/crawl3r/headersarehard    
```
  
### Usage  
  
```
skid@life:~$ echo "www.hackerone.com" | ./headersarehard -q -h secheaders.json 
[HTTP]{S}  Content-Security-Policy
[HTTP]{S}  X-XSS-Protection
[HTTP]{S}  Cache-Control
[HTTP]{S}  Pragma
[HTTP]{S}  Referrer-Policy
[HTTP]{S}  Feature-Policy
[HTTPS]{S}  Content-Security-Policy
[HTTPS]{S}  X-XSS-Protection
[HTTPS]{S}  Cache-Control
[HTTPS]{S}  Pragma
[HTTPS]{S}  Referrer-Policy
[HTTPS]{S}  Feature-Policy
[HTTP]{V}  Server
[HTTPS]{V}  Server  
```
  
Due to the output, we can easily grep for {S} or {V} based on the requirement of Security or Verbose headers.   
  
Before raising these, please check the response packets to ensure what you are seeing here is legit. Just because the tool is printing them doesn't mean they are 'vulnerable' they may just be rocking a slightly different config as headers can make/break web application features. But y'all know that anyway... right?  
  
### License  
  
I'm just a simple skid. Licensing isn't a big issue to me, I post things that I find helpful online in the hope that others can:  
A) learn from the code  
B) find use with the code or  
C) need to just have a laugh at something to make themselves feel better  
  
Either way, if this helped you - cool :)  
