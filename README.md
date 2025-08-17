# GreyNoise Quadrants
1: Requires your GREYNOISE_API_KEY as an environmental variable.\n
2: This script looks for another file /tmp/greytargets.txt, which should be a list of IP addresses, one per line.
3: Once the IP is validated as "noise", other statistics are pulled from the API.
4: The statistics are put through simple math equations and a value of greyFocus and greyTime are calculated for each IP
5: The outfile from the script then needs to be transferred to your Splunk Server so it can be rendered on the dashboard in one of the four "Noise Quadrants". I use Ansible for this.

