#!/bin/bash

###
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

#=========================================================================================================
# Program: install_sms.sh
#
# Ver         Date            Author          Comment
# =======     ===========     ===========     ==========================================
# V1.0.00     2019-04-24      DW              Determine currently running platform and switch to corresponding
#                                             SMS installation script.
# V1.0.01     2019-04-25      DW              Include Debian Linux 9 as SMS supported platform.
# V1.0.02     2019-05-17      DW              Let user select desired web server for SMS installation on CentOS 7.
# V1.0.03     2019-05-21      DW              Let user select desired web server for SMS installation on Debian 9 and Ubuntu 18.04.
# V1.0.04     2019-10-02      DW              Include CentOS Linux 8 as SMS supported platform.
# V1.0.05     2020-07-15      DW              Include Ubuntu 20.04 as SMS supported platform. 
# V1.0.06     2020-12-20      DW              Include CentOS Stream 8 as SMS supported platform.
# V1.0.07     2021-04-03      DW              Include AlmaLinux 8.x as SMS supported platform.
# V1.0.08     2021-07-04      DW              Include Rocky Linux 8.x as SMS supported platform. 
# V1.0.09     2021-08-30      DW              Include Debian 11 as SMS supported platform.
# V1.0.10     2021-10-25      DW              Include Oracle Linux 8.x as SMS supported platform.
# V1.0.11     2022-02-01      DW              Remove CentOS Linux 8 as SMS supported platform since it has passed it's EOL date (2021-12-31).
# V1.0.12     2022-05-12      DW              Remove Debian 9 as SMS supported platform since it has passed it's EOL date.
# V2.0.00     2023-04-28      DW              Totally rewrite for SMS 2.0. Supported platforms are Rocky Linux 8.x, AlmaLinux 8.x (beta) and
#                                             Ubuntu Linux 22.04.
#=========================================================================================================

#-- Don't let screen blank --#
setterm -blank 0

clear

v=`hostnamectl | grep "Rocky Linux 8" | wc -l`
if [[ "$v" -eq 1 ]]
then
  chmod +x ./install_sms2_rocky_linux_8.sh
  source ./install_sms2_rocky_linux_8.sh
  exit 0
fi

#-- AlamLinux 8.x support is still in beta stage --#
v=`hostnamectl | grep "AlmaLinux 8" | wc -l`
if [[ "$v" -eq 1 ]]
then
  chmod +x ./install_sms2_almalinux_8.sh
  source ./install_sms2_almalinux_8.sh
  exit 0
fi

v=`hostnamectl | grep "Ubuntu 22.04" | wc -l`
if [[ "$v" -eq 1 ]]
then
  chmod +x ./install_sms2_ubuntu_22.sh
  source ./install_sms2_ubuntu_22.sh
  exit 0
fi

echo "You are currently running" `hostnamectl | grep "Operating System"`
echo "Which is not supported by SMS 2.0 yet."
exit 1

