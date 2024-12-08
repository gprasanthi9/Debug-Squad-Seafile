Initially I thought Github would have some good modules for C  This resuled in my first challend the default codeql does is not able to process the code.  The second challenge was to find a free tool listed in the other tools, I was able to find Devskim.  Third challenge was figuring out how to install and run it.

Was able to load Devskim module and get it to run against the code.  This lead to my fourth challenge, I didn't think it had run and given me any results.   After discussion with my group and trying to explain what I had done, I realized either the scan had not finished or I looked in the wrong location.

Devskim found 905 errors, but only 5 unique ones and nothing to significant.  The next problem for me was understanding C at a indepth enough level to determine if it was secure.  

From the groups findings I focused on 
Taking the hard-coded credentials, was something I felt was in my realm.  My initial look led me to believe it was a false positive.  Following the instructions, I tooks some of the commands and code and asked about it with ChatGPT, I quickly realized the code was perhaps better than I thought utilizing g_free which is memory wiping.  One suggestion for more security is to use memset_s to further ensure the structure is cleared when not in use.  

As a way to contribute to the Seafile project would be;  more comments in the code to help novices like me understand all that is happening.