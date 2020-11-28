#!/bin/bash

logo(){

echo  '                                                        ';

echo -e '\e[34m        _____       _____   __________   __________    __________  ' ;
echo -e '\e[34m       [     \     [     ] [    __    ] [    __    ]  [    __    \  ';
echo -e '\e[34m       [ + +  \     [ + ]  [ + ]  [ + ] [ + ]  [ + ]  [ + ]  [ + ]   ';
echo -e '\e[36m       [ + ]\  \    [ + ]  [ + ]  [ + ] [ + ]  [ + ]  [ + ]  [ + ]  ';
echo -e '\e[36m       [ + ] \  \   [ + ]  [ + ]  [ + ] [ + ]  [ + ]  [ + ]__[ + ]   ___     ___ '; 
echo -e '\e[32m       [ + ]  \  \  [ + ]  [ + ]  [ + ] [ + ]  [ + ]  [    __   <   [_  ]   [ __] ';
echo -e '\e[32m       [ + ]   \  \ [ + ]  [ + ]  [ + ] [ + ]  [ + ]  [ + ]  [ + ]    [+]   [+] ';
echo -e '\e[35m       [ + ]    \  \[ + ]  [ + ]  [ + ] [ + ]  [ + ]  [ + ]  [ + ]      _]+[_  ';
echo -e '\e[35m       [ + ]     \  + + ]  [ + ]__[ + ] [ + ]__[ + ]  [ + ]__[ + ]   _[+]   [+]_  ';
echo -e '\e[35m      [_____]     \_____]  [__________] [__________]  [__________/  [___]   [___]      ';
echo  '                                                        ';
echo  '                                                        ';
  
echo -e '\e[97m                             v 1.0   # Coded By Gaurav Popalghat - @N008x ';

}

logo


echo "                                                                              "
echo "                                                                              "

echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "                                                                                           "
echo "                                                                                           "
echo "                             Recon For Subdomains ...                                      "
echo "                                                                                           "
echo "                                                                                           "
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"

dir=~/Desktop/recon/$1
mkdir $dir
mkdir $dir/js



python3 ~/Desktop/Sublist3r/sublist3r.py -d $1 -o $dir/$1_subd
echo "                                                                                           "
echo "                                                                                           "
echo "                                                                                           "
echo "                          Collecting from Censys.io ...                                         "
echo "                                                                                           "
echo "                                                                                           "


python3 ~/Desktop/censys-subdomain-finder/censys_subdomain_finder.py $1 --censys-api-id f908f760-5346-481d-ae60-c409c13299ec --censys-api-secret K20muYCbgRb7qzuoeqMPczhf8FCRgjb1 > $dir/censys_subd;

awk -F" " '{print $2}' $dir/censys_subd
sed -e "s/Found//g" -i.backup $dir/censys_subd
sed -e "s/Searching//g" -i.backup $dir/censys_subd | tee -a  $dir/$1_subd  

rm $dir/censys_subd
rm $dir/censys_subd.backup



echo "                                                                                           "
echo "                                                                                           "
echo "                          Collecting from Subfinder ...                                                             "
echo "                                                                                           "
echo "                                                                                           "

subfinder -d $1 | tee -a $dir/$1_subd;

echo "                                                                                           "
echo "                                                                                           "
echo "                          Collecting from Assetfinder ...                                       "
echo "                                                                                           "
echo "                                                                                           "

assetfinder $1 | tee -a $dir/$1_subd;

echo "                                                                                           "
echo "                                                                                           "
echo "                          Collecting from Crt.sh ...                                            "
echo "                                                                                           "
echo "                                                                                           "

curl -s https://crt.sh/?q=%25.$1 | grep "$1" | grep "<TD>" | cut -d ">" -f2 | cut -d"<" -f1 | sort -u | 
sed s/*.//g | tee -a $dir/$1_subd;

echo "                                                                                           "
echo "                                                                                           "
echo "                          Collecting from Certspotter ...                                       "
echo "                                                                                           "
echo "                                                                                           "

curl -s "https://certspotter.com/api/v0/certs?domain=$1" | ~/Desktop/jq-linux64 -c '.-[].dns_names' | tee -a $dir/$1_subd;


echo "                                                                                           "
echo "                                                                                           "
echo "                          Finalizing with unique subdomains ...                                                                "
echo "                                                                                           "
echo "                                                                                           "


cat $dir/$1_subd | sort -u | tee $dir/$1_subdomains;
cat $dir/$1_subdomains | httpx -follow-redirects -status-code -vhost -threads 300 -silent| sort -u | grep "[200]" | cut -d [ -f1 | sort -u | tee -a $dir/$1_resolved

echo "                                                                                           "
echo "                                                                                           "
echo "                           Gathering js files ...                                       "
echo "                                                                                           "
echo "                                                                                           "


#Gather JSFile links from the target using gau
cat $dir/$1_subdomains | gau | grep ".js$" | uniq | sort | tee -a $dir/js/jslinks;

#Gather JSFile links from the target using subjs
cat $dir/$1_subdomains | subjs | tee -a $dir/js/jslinks;

#check for live links
cat $dir/js/jslinks | hakcheckurl | grep "200" | cut -d" " -f2 | sort -u > $dir/js/live_jslinks

echo "                                                                                           "
echo "                                                                                                                                           "
echo "                           Looking for sensitive enpoints ...                                       "
echo "                                                                                                                                           "
echo "                                                                                           "


#sensitive enpoints
cat $dir/js/live_jslinks | while read url; do python3 ~/Desktop/LinkFinder/linkfinder.py -d -i $url -o cli; done > $dir/enpoint.txt

echo "                                                                                           "
echo "                                                                                                                                           "
echo "                           Looking for sensitive information ...                                       "
echo "                                                                                                                                           "
echo "                                                                                           "


#secrets 
cat $dir/js/live_jslinks | while read url; do python3 ~/Desktop/SecretFinder/SecretFinder.py -i $url -o cli > $dir/js_secret.txt; done 

echo "                                                                                           "
echo "                                                                                                                                           "
echo "                           Looking for sensitive information on github ...                                       "
echo "                                                                                                                                           "
echo "                                                                                           "


python3 ~/Desktop/GitDorker/GitDorker.py -tf ~/Desktop/Bug_Bounty/Notes/github_access_token.txt  -q $1 -d ~/Desktop/GitDorker/Dorks/alldorks.txt | tee -a $dir/$1_gitdork


echo "                                                                                           "
echo "                                                                                                                                           "
echo "                           Looking for slowloris dos attack ...                                       "
echo "                                                                                                                                           "
echo "                                                                                           "



cat $dir/$1_subdomains | while read sub; do nmap -sV --script http-slowloris-check $sub -Pn; done > $dir/$1_slowloris.txt


echo "                                                                                           "
echo "                                                                                                                                        "
echo "                           Looking for sensitive open ports ...                                       "
echo "                                                                                           "
echo "                                                                                                                                           "


nmap -sn -Pn -n -iL $dir/$1_subdomains -oG $dir/out.txt

awk -F" " '{print $2}' $dir/out.txt > $dir/outnew.txt

sed -e "s/Nmap//g" -i.backup $dir/outnew.txt 

masscan -iL $dir/outnew.txt --ports 0-65535 > $dir/$1_portscan.txt

rm $dir/out.txt

rm $dir/outnew.txt

rm $dir/outnew.txt.backup
 

echo "                                                                                           "
echo "                                                                                                                                           "
echo "                           Looking for sensitive directories ...                                       "
echo "                                                                                           "
echo "                                                                                                                                           "

cat $dir/$1_subdomains | while read sub; do ~/Desktop/dirsearch/dirsearch.py --url $sub -e php; done > $dir/$1_directory.txt

echo "                                                                                           "
echo "                                                                                                                                           "
echo "                             Recon Complete successfully !                                       "
echo "                                                                                           "
echo "                                                                                                                                           "



