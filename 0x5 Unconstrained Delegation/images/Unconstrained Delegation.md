## Preliminary
### Double Hop
Kerberos protokolü doğası gereği istemci sunucuya erişim sağlarken kullandığı bilgilerle sunucunun erişmek istediği başka bir sunucuya erişim sağlayamaması üzerine Double Hop sorunu ortaya çıkmıştır.
Sunucu istemcinin bilgilerini kullanarak başka bir sunucuya erişebilmesi Delagasyon tanımlayarak gerçekleşmektedir.

Microsoft bu problemi çözebilmek için çeşitli yöntemler geliştirmiştir.
a. Uncostrained Delegation(Kısıtlamasız Delegasyon)
b. Constarined Delegation(Kısıtlamalı delegasyon)

Biz bloğumuzda Uncostrained Delegation(Kısıtlamasız Delegasyon) konusunu ele alacağız.

### Uncostrained Delegation


## Mitigation 

a. Aşağıdaki powershell betiğinden yararlanarak domain üzerindeki kısıtlamasız delegasyon(Unconstrained Delegation) özelliği aktif edilmiş bilgisayarlar tespit edilebilmektedir.

**Not:** Get-ADUser ve Get-ADComputer cmdletleri Powershell ActiveDirectory modülü içerisinde bulunmaktadır. Bu nedenle eğer komut Domain Controller dışında çalıştırılacaksa, bu modül manuel olarak yüklenmelidir.

```Powershell
#Unconstrained Delegation Enabled Computer 
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and Primarygroupid -neq 515} -Properties trustfordelegation,serviceprincipalname,description
```

b. Aşağıdaki powershell betiğinden yararlanarak domain üzerindeki kısıtlamasız delegasyon(Unconstrained Delegation) özelliği aktif edilmiş kullanıcılar tespit edilebilmektedir.

```Powershell
#Unconstrained Delegation Enabled Computer 
Get-ADUser -Filter {TrustedForDelegation -eq $true -and Primarygroupid -neq 513} -Properties trustfordelegation,serviceprincipalname,description
```


index="wineventlog" EventCode=4769 Service_Name=krbtgt Ticket_Options=0x60810010 NOT Account_Name="*$*"
## Reference 

- https://adsecurity.org/?p=1667
- https://medium.com/r3d-buck3t/attacking-kerberos-unconstrained-delegation-ef77e1fb7203
- https://social.msdn.microsoft.com/Forums/en-US/dc7b0981-0aa8-4823-836f-6430ff8a3f4e/active-directory-ldap-property-primarygroupid?forum=netfxnetcom #Groupid biligileri