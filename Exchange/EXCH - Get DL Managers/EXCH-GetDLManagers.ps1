get-distributiongroup -resultsize unlimited |

     ForEach-Object{

            # here get the group name and use the "managedBy attribute to retrieve the user object
            # grou naem
            $gname = $_.Name

            $manager=Get-AdUser $_.ManagedBy

            $MangerName = $manager.DisplayName

     }