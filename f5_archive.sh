#!/bin/bash

# Archive UCS to host1

HOSTNAME=$(cat /var/prompt/hostname)
STATUS=$(cat /var/prompt/ps1)
TIMESTAMP=$(date +%Y%m%d)
OUTPUT_DIR=/var/tmp
OUTPUT_FILE=${HOSTNAME}_${STATUS}_${TIMESTAMP}.ucs
KEY_FILE=/home/removed/.ssh/id_rsa
LOG_FILE=${OUTPUT_DIR}/push_archive_${TIMESTAMP}.log
FREE=$(df /var/tmp | awk -F' ' '{print $4}' | tail -1 )
DST_HOST='host1.some.domain.com'
RECIPIENTS=removed@some.domain.com


# Making sure /var/tmp has at least 2GB storage
if [[ $FREE -ge 2000000 ]];
  then
    ls -larth ${OUTPUT_DIR}/${HOSTNAME}_*.ucs.gz
    if [[ $? == 0 ]];
      then
        printf "Removing old archives matching pattern ${HOSTNAME}_*.ucs.gz\n"
        rm /var/tmp/${HOSTNAME}_*.ucs.gz
    fi
    printf "Writing UCS archive to: /var/tmp/${HOSTNAME}_${STATUS}_${TIMESTAMP}.ucs\n" | tee -a ${LOG_FILE}
    tmsh save /sys ucs ${OUTPUT_DIR}/${OUTPUT_FILE} passphrase removed | tee -a ${LOG_FILE}
    if [[ $? == 0 ]];
      then
        printf "Compressing to ${OUTPUT_DIR}/${OUTPUT_FILE}.gz\n" | tee -a ${LOG_FILE}
        gzip ${OUTPUT_DIR}/${OUTPUT_FILE} | tee -a ${LOG_FILE}
        LOCAL_CHKSUM=$(md5sum ${OUTPUT_DIR}/${OUTPUT_FILE}.gz | cut -d' ' -f1)
        printf "${HOSTNAME}: ${LOCAL_CHKSUM} | tee -a ${LOG_FILE}"
        scp -o IdentityFile=${KEY_FILE} ${OUTPUT_DIR}/${OUTPUT_FILE}.gz removed@${DST_HOST}:/removed/config-backups/${OUTPUT_FILE}.gz | tee -a ${LOG_FILE}
        DST_CHKSUM=$(ssh -l removed -i ${KEY_FILE} ${DST_HOST} "md5sum /removed/config-backups/${OUTPUT_FILE}.gz" | cut -d ' ' -f 1)
        if [[ -z ${DST_CHKSUM} ]];
          then
             printf "UCS archive failed transfer to ${DST_HOST}" | tee -a ${LOG_FILE}
             tail -1 ${LOG_FILE} | mail -vs "${HOSTNAME} UCS Archive" ${RECIPIENTS}
             exit 1
          fi
        printf "${HOSTNAME}: ${DST_CHKSUM} | tee -a ${LOG_FILE}"
        if [[ ${LOCAL_CHKSUM} == ${DST_CHKSUM} ]];
          then
             printf "UCS archive passed checksum validation and copied to: /removed/config-backups/${OUTPUT_FILE}.gz\n" | tee -a ${LOG_FILE}
             tail -1 ${LOG_FILE} | mail -vs "${HOSTNAME} UCS Archive" ${RECIPIENTS}
          else
             ssh -l removed -i ${KEY_FILE} ${DST_HOST} "rm /removed/config-backups/${OUTPUT_FILE}.gz"
             printf "UCS archive failed!\nChecksum validation error: ${LOCAL_CHKSUM} != ${DST_CHKSUM}\nRemoved file: /removed/config-backups/${OUTPUT_FILE}.gz\n" | tee -a ${LOG_FILE}
             tail -3 ${LOG_FILE} | mail -vs "${HOSTNAME} UCS Archive" ${RECIPIENTS}
        fi
    fi
  else
    printf "Not enough space to write UCS archive: ${FREE}G" | tee -a ${LOG_FILE}
    tail -1 ${LOG_FILE} | mail -vs "${HOSTNAME} UCS Archive" ${RECIPIENTS}
    exit 1
  fi
exit 0
