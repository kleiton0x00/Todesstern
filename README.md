# Todesstern
Todesstern (in english: Death Star) is a simple mutator engine which focuses on finding unknown classes of injection vulnerabilities. The script generates tons of mutated payloads from a user-given string, which are used to find anomalies.
**Note:** While this tool helps you on finding anomalies, it is your job to further analyze the output which *might* lead to vulnerabilities. It is highly recommended to practice this tool with the [Portswigger Labs](https://portswigger.net/web-security/all-labs) before going on real-targets to understand what is going on.

# Engine Setup
Make sure to configure the engine by making changes to *config.ini* to your liking before using it. The default values are what I recommend for standard Web application testing, however adjustements can be made. The following are the options which can be customized:  

`canary` - (Default: `canary`): a value used to grep the output for analysis, this is added before and after the mutated string. For example: *canaryhelloworldcanary*  
`input_string` - the string which will be mutated, can be a simple string or a custom payload you want to further test  `fuzzer_engine` - (options: essential/all): the option to generate the mutated payloads. If set to `essential` (default), the engine generates fewer but more precise mutated payloads. This option is highly recommended for webapp pentesting. If set to `all`, the engine generates more payloads suitable for testing againts buffer overflow, resource-intensive-task handling or any crash-related bugs (such as DOS).  
`payload_complexity`: (options: low/high): If set to `low`, the engine mutates the raw input once. Else if set to `high`, the engine takes mutated payloads and send them to another mutation-cycle.  
`mutation_rate`: (Default: `0.2`): The value can be from 0 to 1, where 0 is a barely mutated payload and 1 is highly mutated payload. Payloads might get longer when mutation_rate is set to a large value.  
`max_mutations`: (Default: `20`): Ammount of mutated strings generated per mutation rules.  

# Usage  
**Todesstern** doesn't require any dependency. Once you finish configuring the *config.ini* file, you can execute the script by running `python3 todesstern.py`. The engine will save the mutated payloads in `mutations.txt`. It is recommended to run the script more than one time (no worries, the output is overwritten in the file) to get a good variety of mutations.  
On [Burp Suite](https://portswigger.net/burp), send your desired HTTP Request to Intruder, go to **Positions** tab and mark the payload which is going to be replaced by the mutated ones. Then go to **Settings** tab, scroll down to **Grep - Ectract** and click on **Add** button. On the right side of the popped-up tab, paste the following regex (make sure `canary` matches your canary).:
```
canary(.*?)canary
```
It should look like the following image:  
![regex_canary](https://github.com/kleiton0x00/Todesstern/blob/main/static/Screenshot%20from%202023-09-15%2012-49-07.png?raw=true)  

Click **OK** and you should have a grep item added:  
![grep_item_added](https://github.com/kleiton0x00/Todesstern/blob/main/static/Screenshot%20from%202023-09-15%2012-51-37.png?raw=true)  

Go to **Payloads** tab and load the file `mutations.txt`. If everything went fine, you will have the payloads loaded:  
![payloads_loaded](https://github.com/kleiton0x00/Todesstern/blob/main/static/Screenshot%20from%202024-03-17%2023-48-52.png?raw=true)  

Go back to **Positions** tab and start the attack. On the results' table, focus on `Payloads` and `canary(.*?)canary` columns and compare the data with eachother:    
![results_table](https://github.com/kleiton0x00/Todesstern/blob/main/static/Screenshot%20from%202023-09-15%2012-49-50.png?raw=true)  

# Demo
Here is a SSTI's anomaly on Ruby (`<%` is removed):  
![ruby_ssti_anomaly](https://github.com/kleiton0x00/Todesstern/blob/main/static/ruby_ssti_anomaly.jpg?raw=true)  

# References
https://github.com/PortSwigger/backslash-powered-scanner  
