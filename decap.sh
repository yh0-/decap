#!/bin/sh
#
# Utility for airdecap-ng
# Resources and thanks: wifizoo, rummage
# Licence: GPLv3
# yh0- (yysjryysjr AT gmail DOT COM) 2014
#

log="${log:-/tmp/$(basename "$0")}"
oui="/etc/aircrack-ng/airodump-ng-oui.txt"
user=""
verbose=false
airdecap_opts=""
browser="firefox" #"google-chrome"

if [ "$(id -u)" != "0" ]
then
    printf "Run it as root\n"
    exit 1
fi

progs=""
for prog in capinfos airdecap-ng p0f wash
do
  if [ ! -x "$(command -v $prog 2>&1)" ]
  then
      progs="$progs $prog"
  fi
done

if [ -n "$progs" ]
then
    for prog in $progs; do printf "$prog not found\n"; done
    exit 1
fi

if [ ! -f "$oui" ]
then
    printf "IEEE OUI file does not exist. "
    printf "You might want to run airodump-ng-oui-update first.\n"
    printf "Or edit 'oui' var to sane value.\n"
    exit 1
fi

if [ ! -x "$(command -v airgraph-ng 2>&1)" ]
then
    printf "airgraph-ng not found\n"
else
    if [ ! -f /usr/local/share/airgraph-ng/oui.txt ]
    then
        ln -s "$oui" /usr/local/share/airgraph-ng/oui.txt
    fi
fi

sux=""
if [ -x "$(command -v sux 2>&1)" ]
then
    if [ "x$user" != "x" ]
    then
        if ! ls /home 2> /dev/null | grep -q "$user$"
        then
            echo "No such user: $user"
            exit 1
        fi
        sux="sux - $user"
    fi
fi

usage ()
{
    printf "Usage: $(basename "$0") [options] <pcap file>\n"
    printf "  Common options:\n"
    printf "      -v         : verbose mode\n"
    printf "$1\n" | grep -v -i "\-ng\|common" | grep '.'
}

start_http_server ()
{
    if [ ! -d "$log" ]
    then
        return
    fi

    title="Capture Report"
    cat << EOF > $log/index.html
<html>
<head>
<title>$title</title>
<style type="text/css">
 body, div, td { font-size: 12px; color: #666666; }
 b { color: #333333; }
 .indent { margin-left: 10px; }
</style>
</head>

<body link="#993300" vlink="#771100" alink="#ff6600">

<table border="0" width="100%" height="95%"><tr><td align="center" valign="middle">
<div style="width: 500px; background-color: #eeeeee; border: 1px dotted #cccccc; padding: 20px; padding-top: 15px;">
 <div align="center" style="font-size: 14px; font-weight: bold;">
  $title
 </div>

 <div align="left">
  <p> Date:  $(date) </p>
  <p> $(cat ${capinfos_log}.html) </p>
EOF

    if [ "x$total_ap" != "x" ]
    then
        cat << EOF >> $log/index.html
  <p> Total Access Point(s):  $total_ap <br> 
EOF
    fi

    if [ -e "${airdecap_stdout}.html" ]
    then
        cat << EOF >> $log/index.html
  <p> $(cat ${airdecap_stdout}.html) </p>
EOF
    fi

    cat << EOF >> $log/index.html
  <p> Generated files:<br>

  <table class="indent" border="0" cellspacing="3">
EOF

    for u in $url
    do
      x="http://127.0.0.1:8000/$(basename $u)"
      if [ "$u" = "${capinfos_log}.html" ]
      then
          :
      elif [ "$u" = "${airdecap_stdout}.html" ]
      then
          :
      elif [ "$u" = "${airodump_csv_mod}.html" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">AP-Client List</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$capr" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Client-AP Relation Graph</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$cpg" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Client Probe Graph</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$log/${cap_name}.kismet.netxml.xml" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Kismet Netxml</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$log/${cap_name}.kismet.csv.html" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Kismet CSV</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$log/${cap_name}.netxml.xml" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Kismet Net XML</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$log/${cap_name}.nettxt.html" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Kismet Net Text</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$log/${cap_name}.gpsxml.xml" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Kismet GPS XML</a></b></td>
   </tr>
EOF

      elif [ "$u" = "$log/${cap_name}.alert.html" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">Kismet Alert</a></b></td>
   </tr>
EOF


      elif [ "$u" = "${p0f_stdout}" ]
      then
          cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">p0f ($(echo "$p0f_stat" | sed 's/All done. //'))</a></b></td>
   </tr>
EOF

      elif [ "$u" = "${p0f_log}" ]
      then
          if [ -s "$p0f_log" ]
          then
              cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="$x">p0f Log</a></b></td>
   </tr>
EOF
          fi
      fi
    done


    if [ -d "$log/${decap_name}" ]
    then
        cat << EOF >> $log/index.html
   <tr>
    <td><b><a href="http://127.0.0.1:8000/${decap_name}">Misc</a></b></td>
   </tr>
EOF
    fi

    cat << EOF >> $log/index.html
  </table>
  </p>
 </div>

</div>
</td></tr></table>

</body>
</html>

EOF

    if [ "x$user" != "x" ]
    then
        chown -R $user:$user $log
    fi

    if [ ! -f /tmp/serve.py ]
    then
        cat << EOF > /tmp/serve.py
from SimpleHTTPServer import SimpleHTTPRequestHandler as HandlerClass
from BaseHTTPServer import HTTPServer as ServerClass
ServerClass(('127.0.0.1', 8000), HandlerClass).serve_forever()
EOF
        chmod 644 /tmp/serve.py
    fi

    PID=$(ps aux | grep "python /tmp/serve.py" | grep -v grep | awk '{print $2}')
    if [ "x$PID" = "x" ]
    then
        printf "\nRunning: python /tmp/serve.py.. "
        cd "$log"
        PID=$(python /tmp/serve.py 2> /dev/null > /dev/null & echo $!)
        sleep 1s
        cd - > /dev/null
    fi

    if [ "x$PID" != "x" ]
    then
        printf "HTTP Server is running.. DIR: $log PID: $PID\n"
        printf "Open browser at 127.0.0.1:8000\n"
        printf "To stop the HTTP Server, run:\nkill $PID\n"
    fi
}

txt2html ()
{
    sed -e '1i\
<?xml version="1.0" encoding="UTF-8"?>\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "DTD/xhtml1-strict.dtd">\
<html xmlns="http://www.w3.org/1999/xhtml">\
<head>\
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />\
</head>\
<body>\
<pre>' -e '$a\
</pre>\
</body> ' "$1"
}

show ()
{
    start_http_server

    if [ "x$DISPLAY" = "x:0" ]
    then
        :
    else
        if [ ! -x "$(command -v $browser 2>&1)" ]
        then
            printf "$browser not found\n"
        else
            PID=$(ps aux | grep "$browser" | grep -v grep | awk '{print $2}')
            if [ "x$PID" = "x" ]
            then
                url_base="http://127.0.0.1:8000"
                #for u in $url; do url_base="$url_base http://127.0.0.1:8000/$(basename $u)"; done
                exec $sux $browser $url_base 2> /dev/null > /dev/null &
                sleep 1s
            fi
        fi
    fi
}

while [ $# -gt 0 ]
do
  case "$1" in
  -b | -e | -w | -p | -k )
      opt="$1"
      shift
      if test $# = 0
      then
          printf "Missing argument for '$opt'\n"
          exit 1
      fi
      case "$1" in
      -* )
          printf "Missing argument for '$opt'\n"
          exit 1 ;;
      esac
      case "$opt" in
      -b ) bssid="$1" ;;
      -e ) essid="$1" ;;
      -w ) wep_key="$1" ;;
      -p ) wpa_pass="$1" ;;
      -k ) wpa_pmk="$1" ;;
      esac  

      case "$opt" in
      -e )
          if echo "$essid" | grep -q "[[:space:]]"
          then
              essid="\"$essid\""
          fi
          airdecap_opts="$airdecap_opts $opt $essid"
          ;;
      * )
          airdecap_opts="$airdecap_opts $opt $1"
          ;;
      esac
      shift ;;
  -l )
      shift
      airdecap_opts="$airdecap_opts -l" ;;
  -v | --verbose )
      shift
      verbose=true ;;
  -V | --version )
      airdecap-ng | head -n2
      wash -h 2>&1 | head -n4  | sed 's/^/  /'
      p0f -v 2>&1 | sed '1q' | sed 's/^/  /'
      exit 0 ;;
  -h | --help )
      usage "$(airdecap-ng --help)"
      exit 0 ;;
  --clean )
      [ -d "$log" ] && rm -r "$log"
      exit 0 ;;
  -- ) # Stop option processing
      shift
      break ;;
  -* )
      printf "Unknown option '$1'\n"
      exit 1 ;;
  * )
      cap="$@"
      if [ ! -f "$cap" ]
      then
          #usage "$(airdecap-ng --help)"
          printf "Need pcap file!\n"
          exit 1
      fi
      break ;;
  esac
done

if [ $# -eq 0 ]
then
    usage "$(airdecap-ng)"
    exit 1
fi

mkdir -p "$log" || exit 1

dirname="$(dirname "$cap")"
basename="$(basename "$cap")"

cap_ext=$(printf "$basename" | awk -F'.' '{print $NF}')
if [ "$cap_ext" = "$basename" -o ${#cap_ext} -gt 4 ]
then
    [ "$cap_ext" = "$basename" ] && cap_name="$basename" || cap_name="${basename%%.$cap_ext}"
    decap="${cap}-dec"
    decap_name="$(basename "$decap")"
else
    cap_name="${basename%%.$cap_ext}"
    decap="$(printf "$cap" | sed "s/\.$cap_ext$/-dec\.$cap_ext/g")"
    basename="$(basename "$decap")"
    decap_name="${basename%%.$cap_ext}"
fi

capinfos_log=$log/${cap_name}.capinfos
printf "\nRunning capinfos:\n"
printf "capinfos -tEkcsdluae $cap\n"
capinfos -tEkcsdluae "$cap" > $capinfos_log
ret=$?
cat $capinfos_log
#if [ $ret -ne 0 ]
#then
#    capinfos -tEkcsdluae "$cap" > $capinfos_log
#fi

encap=$(sed -n -e 's/^File encapsulation://p' < $capinfos_log | sed 's/^[ \t]*//')
txt2html $capinfos_log > ${capinfos_log}.html
url="${capinfos_log}.html"

if [ "$encap" = "Ethernet" ]
then
    decap="$cap"
    decap_name="$(basename "$decap")"
else
    airdecap_stdout="$log"/"$cap_name".airdecap_stdout
    cmd="airdecap-ng $(echo "$airdecap_opts"|sed 's/^[ \t]*//;s/[ \t]*$//') $cap"
    printf "\nRunning airdecap-ng:\n"
    printf "${cmd}\n"
    eval ${cmd} > $airdecap_stdout
    ret=$?
    cat $airdecap_stdout

    if [ $ret -ne 0 ]
    then
        rm $airdecap_stdout
        exit 1
    fi

    airodump_csv=$dirname/${cap_name}.csv
    kismet_netxml=$dirname/${cap_name}.kismet.netxml
    kismet_csv=$dirname/${cap_name}.kismet.csv

    Kismet_netxml=$dirname/${cap_name}.netxml
    Kismet_nettxt=$dirname/${cap_name}.nettxt
    Kismet_gpsxml=$dirname/${cap_name}.gpsxml
    Kismet_alert=$dirname/${cap_name}.alert

    airodump_csv_mod=$log/${cap_name}.csv
    capr=$log/${cap_name}.capr.png
    cpg=$log/${cap_name}.cpg.png

    txt2html $airdecap_stdout | sed 's/\[K//g' > ${airdecap_stdout}.html
    url="$url ${airdecap_stdout}.html"

    if [ ! -f $log/${cap_name}.wps ]
    then
        printf "\nRunning wash:\n"
        printf "wash -f $cap -C -o $log/${cap_name}.wps\n"
        wash -f $cap -C -o $log/${cap_name}.wps > /dev/null 2> /dev/null || > $log/${cap_name}.wps
    fi

    if [ -f "$airodump_csv" ]
    then
        opt_display=0
        opt_pp=0

        printf "\nParsing airodump csv. \n"
        awk -v OUI="$oui" -v WPS="$log/${cap_name}.wps" -v opt_pp="$opt_pp" -v opt_display="$opt_display" '
BEGIN {
	while (getline <OUI) {
		manuf = substr($0,index($0,"(hex)")+5);
		sub(/^[ \t]+/, "", manuf )
		ouilist[substr($0,1,8)] = manuf
	}

	if (system("test -r " WPS) == 0) {
		while (getline <WPS)
		wpslist[$1] = $5 ", " $4
	}
	wpslist["BSSID"] = "WPS Locked, Version"
}

function getmanuf(mac,    x, ouimac) {
	if (mac == "BSSID" || mac == "Station MAC") {
		manuf = "Manuf"
	} else {
		ouimac=substr(mac,1,8)
		gsub(/:/, "-", ouimac)
		manuf = ouilist[ouimac]
		if (length(manuf) == 0) {
			manuf = "\"Unknown\""
		} else {
			manuf = "\"" manuf "\""
		}
	}
	return 0
}

function output(bssid, fts, lts, ch, mb, enc, cipher, auth, pwr, beacons, data, ip, len, ssid, key, m, w) {
	sub(/[0-9]{4}-[0-9]{2}-[0-9]{2}/, "", fts) #19
	sub(/^[ ]/, "", fts) #19
	sub(/^[ ]/, "", lts) #19
	sub(/^[ ]+/, "", ch) #4
	sub(/^[ ]+/, "", mb) #4
	gsub(/^[ ]+|[ ]+$/, "", enc) #8 ?
	sub(/^[ \t]+/, "", cipher) #10
	sub(/^[ \t]+/, "", auth) #4
	sub(/^[ \t]+/, "", pwr)#4
	sub(/^[ \t]+/, "", beacons) #10
	sub(/^[ \t]+/, "", data) #10
	sub(/^[ \t]+/, "", ip) #16
	sub(/^[ \t]+/, "", len) #4
	sub(/^[ \t]+/, "", ssid)
	sub(/\r$/,"", key);
	sub(/^[ \t]+/, "", key)

	if (bssid == "BSSID") {
		fts = " 1st seen"
		ch = "CH"
		mb = "MB"
		enc = "ENC"
		auth = "AUTH"
		pwr = "PWR"
		data = "# Data"
	}

	if (length(ssid) == 0) {
		ssid = "<length " len ">"
	}
	format="%-17s %-8s %-4s %-4s %-8s %-10s %-4s %-4s %-9s %-9s %-18s %s, %s\n";
	printf(format, bssid, fts, ch, mb, enc, cipher, auth, pwr, beacons, data, ssid, m, w);
}

function outputsta(sta, fts, lts, pwr, pkts, bss, probes, m) {
	sub(/[0-9]{4}-[0-9]{2}-[0-9]{2}/, "", fts ) #19
	sub(/^[ ]/, "", fts) #19
	sub(/^[ ]/, "", lts) #19
	sub(/^[ \t]+/, "", pwr) #4
	sub(/^[ \t]+/, "", pkts) #10
	sub(/^[ \t]+|[ \t,]+$/, "", bss) #
	sub(/^[ \t]+/, "", probes)

	if (sta == "Station MAC") {
		fts = "1st seen"
		pwr = "PWR"
	}

	if (length(probes) > 0) {
		probes = " " probes
	}

	format="%-17s %-8s %-4s %-10s %-17s %s %s\n";
	printf(format, sta, fts, pwr, pkts, bss, probes, m);
}

{
	sub(/\r$/,"");
}

{
	if (NF > 7 && NF <= 15) {
		if (opt_display == 2) {
			next
		}
		FS = ","
		getmanuf($1)
		wpsinfo = wpslist[$1]
		if (length(wpsinfo) == 0) {
			wpsinfo = " , "
		}
		if (opt_pp == 0) {
			printf("%s, %s, %s\n", $0, manuf, wpsinfo)
		} else {
			output($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, manuf, wpsinfo)
		}

	} else {
		FS = ", "
		if (NF > 0) {
			if (opt_display == 1) {
				next
			}
			getmanuf($1)
			if (opt_pp == 0) {
				printf("%s , %s\n", $0, manuf)
			} else {
				outputsta($1, $2, $3, $4, $5, $6, $7, manuf)
			}
		} else {
			print
		}
	}
}
' $airodump_csv > $airodump_csv_mod

        total_ap=$(sed -n '/BSSID,/,/Station MAC,/p' < $airodump_csv_mod | grep -v "^BSSID\|^Sta" | awk '{print $1}' | grep  -c ',')

        txt2html $airodump_csv_mod > ${airodump_csv_mod}.html
        url="$url ${airodump_csv_mod}.html"

        if $verbose
        then
            cat $airodump_csv_mod
        fi

        if airgraph-ng 2> /dev/null > /dev/null
        then
            printf "\nRunning airgraph-ng:\n"
            printf "airgraph-ng -o $capr -i $airodump_csv -g CAPR\n"
            airgraph-ng -o $capr -i $airodump_csv -g CAPR 2> /dev/null > /dev/null
            printf "airgraph-ng -o $cpg -i $airodump_csv -g CAPR\n"
            airgraph-ng -o $cpg -i $airodump_csv -g CPG 2> /dev/null > /dev/null
            url="$url $capr $cpg"
        fi
    fi

    if [ -e "$kismet_netxml" ]
    then
        cat $kismet_netxml > $log/${cap_name}.kismet.netxml.xml
        url="$url $log/${cap_name}.kismet.netxml.xml"
    fi

    if [ -e "$kismet_csv" ]
    then
        txt2html $kismet_csv > $log/${cap_name}.kismet.csv.html
        url="$url $log/${cap_name}.kismet.csv.html"
    fi

    if [ -e "$Kismet_netxml" ]
    then
        if [ "x$total_ap" = "x" ]
        then
            total_ap=$(grep -c "<wireless-network number" $Kismet_netxml)
        fi

        cat $Kismet_netxml > $log/${cap_name}.netxml.xml
        url="$url $log/${cap_name}.netxml.xml"
    fi

    if [ -e "$Kismet_nettxt" ]
    then
        if [ "x$total_ap" = "x" ]
        then
            total_ap=$(grep -c "^Network " $Kismet_nettxt)
        fi
        txt2html $Kismet_nettxt > $log/${cap_name}.nettxt.html
        url="$url $log/${cap_name}.nettxt.html"
    fi

    if [ -e "$Kismet_gpsxml" ]
    then
        cat $Kismet_gpsxml > $log/${cap_name}.gpsxml.xml
        url="$url $log/${cap_name}.gpsxml.xml"
    fi

    if [ -e "$Kismet_alert" -a -s "$Kismet_alert" ]
    then
        txt2html $Kismet_alert > $log/${cap_name}.alert.html
        url="$url $log/${cap_name}.alert.html"
    fi

    if [ -n "$wpa_pass" -o -n "$wpa_pmk" ]
    then
        crypto="WPA"
    elif [ -n "$wep_key" ]
    then
        crypto="WEP"
    fi

    if [ "x$crypto" != "x" ]
    then
        num=$(awk -F"Number of decrypted $crypto  packets" "{print \$2}" $airdecap_stdout | awk '/./' | sed 's/^[ \t]*//')
        if [ "$num" = "0" ]
        then
            show
            exit 1
        fi
    fi
fi

p0f_log=$log/${decap_name}.p0f.txt
p0f_stdout=$log/${decap_name}.p0f_stdout.txt
rm $p0f_log 2> /dev/null > /dev/null
printf "\nRunning passive OS finger printing, p0f:\n"
printf "p0f -r $decap -o $p0f_log\n"
p0f -r "$decap" -o $p0f_log > $p0f_stdout || {
    p0f -s "$decap" -o $p0f_log > $p0f_stdout || {
        show
        exit 1
    }
}

url="$url ${p0f_stdout}"

if [ -s "$p0f_log" ]
then
    url="$url ${p0f_log}"
fi

if $verbose
then
    cat $p0f_stdout $p0f_log
fi

p0f_stat=$(tail -n1 $p0f_stdout)

if ! $verbose
then
    echo "$p0f_stat"
fi

if [ -s "$p0f_log" ] && $verbose
then
    printf "\nHint:\ntshark -r $decap | grep ARP\n\n"
fi

if [ "x$(echo "$p0f_stat" | sed 's/All done. Processed //;s/ packets.//')" = "x0" ]
then
    show
    exit 1
fi

mkdir -p $log/${decap_name}

sh="test1.sh"

if [ -x "$sh" ]
then
    printf "\nRunning $sh: \n"
    echo "./$sh "$decap" $log/${decap_name} 2> /dev/null"
    ./$sh "$decap" $log/${decap_name} 2> /dev/null
fi

show

