// Export all available scans

module.exports = {
	aws : {
	    'acmValidation'		            : require(__dirname + '/plugins/aws/acm/acmValidation.js'),
	    'asgMultiAz'                    : require(__dirname + '/plugins/aws/autoscaling/asgMultiAz.js'),
	    'publicS3Origin'                : require(__dirname + '/plugins/aws/cloudfront/publicS3Origin.js'),
	    'secureOrigin'                  : require(__dirname + '/plugins/aws/cloudfront/secureOrigin.js'),
	    'insecureProtocols'             : require(__dirname + '/plugins/aws/cloudfront/insecureProtocols.js'),
	    'cloudfrontHttpsOnly'           : require(__dirname + '/plugins/aws/cloudfront/cloudfrontHttpsOnly.js'),
	    'cloudfrontLoggingEnabled'      : require(__dirname + '/plugins/aws/cloudfront/cloudfrontLoggingEnabled.js'),

	    'cloudtrailBucketAccessLogging' : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailBucketAccessLogging.js'),
	    'cloudtrailBucketDelete'        : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailBucketDelete.js'),
	    'cloudtrailEnabled'             : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailEnabled.js'),
	    'cloudtrailEncryption'          : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailEncryption.js'),
	    'cloudtrailFileValidation'      : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailFileValidation.js'),
	    'cloudtrailToCloudwatch'        : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailToCloudwatch.js'),
	    'cloudtrailBucketPrivate'       : require(__dirname + '/plugins/aws/cloudtrail/cloudtrailBucketPrivate.js'),

	    'configServiceEnabled'          : require(__dirname + '/plugins/aws/configservice/configServiceEnabled.js'),

	    'defaultSecurityGroup'          : require(__dirname + '/plugins/aws/ec2/defaultSecurityGroup.js'),
	    'elasticIpLimit'                : require(__dirname + '/plugins/aws/ec2/elasticIpLimit.js'),
	    'subnetIpAvailability'          : require(__dirname + '/plugins/aws/ec2/subnetIpAvailability.js'),
	    'excessiveSecurityGroups'       : require(__dirname + '/plugins/aws/ec2/excessiveSecurityGroups.js'),
	    'instanceLimit'                 : require(__dirname + '/plugins/aws/ec2/instanceLimit.js'),
	    'instanceMaxCount'              : require(__dirname + '/plugins/aws/ec2/instanceMaxCount.js'),
	    'instanceKeyBasedLogin'         : require(__dirname + '/plugins/aws/ec2/instanceKeyBasedLogin.js'),
	    'openAllPortsProtocols'         : require(__dirname + '/plugins/aws/ec2/openAllPortsProtocols.js'),
	    'openCIFS'                      : require(__dirname + '/plugins/aws/ec2/openCIFS.js'),
	    'openDNS'                       : require(__dirname + '/plugins/aws/ec2/openDNS.js'),
	    'openFTP'                       : require(__dirname + '/plugins/aws/ec2/openFTP.js'),
	    'openMySQL'                     : require(__dirname + '/plugins/aws/ec2/openMySQL.js'),
	    'openOracle'                    : require(__dirname + '/plugins/aws/ec2/openOracle.js'),
	    'openNetBIOS'                   : require(__dirname + '/plugins/aws/ec2/openNetBIOS.js'),
	    'openPostgreSQL'                : require(__dirname + '/plugins/aws/ec2/openPostgreSQL.js'),
	    'openRDP'                       : require(__dirname + '/plugins/aws/ec2/openRDP.js'),
	    'openRPC'                       : require(__dirname + '/plugins/aws/ec2/openRPC.js'),
	    'openSMBoTCP'                   : require(__dirname + '/plugins/aws/ec2/openSMBoTCP.js'),
	    'openSMTP'                      : require(__dirname + '/plugins/aws/ec2/openSMTP.js'),
	    'openSQLServer'                 : require(__dirname + '/plugins/aws/ec2/openSQLServer.js'),
	    'openSSH'                       : require(__dirname + '/plugins/aws/ec2/openSSH.js'),
	    'openTelnet'                    : require(__dirname + '/plugins/aws/ec2/openTelnet.js'),
	    'openVNCClient'                 : require(__dirname + '/plugins/aws/ec2/openVNCClient.js'),
	    'openVNCServer'                 : require(__dirname + '/plugins/aws/ec2/openVNCServer.js'),
	    'openElasticsearch'             : require(__dirname + '/plugins/aws/ec2/openElasticsearch.js'),
	    'vpcElasticIpLimit'             : require(__dirname + '/plugins/aws/ec2/vpcElasticIpLimit.js'),
	    'classicInstances'              : require(__dirname + '/plugins/aws/ec2/classicInstances.js'),
	    'flowLogsEnabled'               : require(__dirname + '/plugins/aws/ec2/flowLogsEnabled.js'),
	    'vpcMultipleSubnets'            : require(__dirname + '/plugins/aws/ec2/multipleSubnets.js'),
	    'overlappingSecurityGroups'     : require(__dirname + '/plugins/aws/ec2/overlappingSecurityGroups.js'),
	    'publicAmi'                     : require(__dirname + '/plugins/aws/ec2/publicAmi.js'),
	    'encryptedAmi'                  : require(__dirname + '/plugins/aws/ec2/encryptedAmi.js'),
	    'instanceIamRole'               : require(__dirname + '/plugins/aws/ec2/instanceIamRole.js'),
	    'ebsEncryptionEnabled'          : require(__dirname + '/plugins/aws/ec2/ebsEncryptionEnabled.js'),
	    'natMultiAz'                    : require(__dirname + '/plugins/aws/ec2/natMultiAz.js'),
	    'defaultVpcInUse'               : require(__dirname + '/plugins/aws/ec2/defaultVpcInUse.js'),
	    'crossVpcPublicPrivate'         : require(__dirname + '/plugins/aws/ec2/crossVpcPublicPrivate.js'),
	    'ebsEncryptedSnapshots'         : require(__dirname + '/plugins/aws/ec2/ebsEncryptedSnapshots.js'),

	    'insecureCiphers'               : require(__dirname + '/plugins/aws/elb/insecureCiphers.js'),
	    'elbHttpsOnly'                  : require(__dirname + '/plugins/aws/elb/elbHttpsOnly.js'),
	    'elbLoggingEnabled'             : require(__dirname + '/plugins/aws/elb/elbLoggingEnabled.js'),
	    'elbNoInstances'                : require(__dirname + '/plugins/aws/elb/elbNoInstances.js'),

	    'accessKeysExtra'               : require(__dirname + '/plugins/aws/iam/accessKeysExtra.js'),
	    'accessKeysLastUsed'            : require(__dirname + '/plugins/aws/iam/accessKeysLastUsed.js'),
	    'accessKeysRotated'             : require(__dirname + '/plugins/aws/iam/accessKeysRotated.js'),
	    'certificateExpiry'             : require(__dirname + '/plugins/aws/iam/certificateExpiry.js'),
	    'emptyGroups'                   : require(__dirname + '/plugins/aws/iam/emptyGroups.js'),
	    'iamUserAdmins'                 : require(__dirname + '/plugins/aws/iam/iamUserAdmins.js'),
	    'maxPasswordAge'                : require(__dirname + '/plugins/aws/iam/maxPasswordAge.js'),
	    'minPasswordLength'             : require(__dirname + '/plugins/aws/iam/minPasswordLength.js'),
	    'noUserIamPolicies'             : require(__dirname + '/plugins/aws/iam/noUserIamPolicies.js'),
	    'passwordExpiration'            : require(__dirname + '/plugins/aws/iam/passwordExpiration.js'),
	    'passwordRequiresLowercase'     : require(__dirname + '/plugins/aws/iam/passwordRequiresLowercase.js'),
	    'passwordRequiresNumbers'       : require(__dirname + '/plugins/aws/iam/passwordRequiresNumbers.js'),
	    'passwordRequiresSymbols'       : require(__dirname + '/plugins/aws/iam/passwordRequiresSymbols.js'),
	    'passwordRequiresUppercase'     : require(__dirname + '/plugins/aws/iam/passwordRequiresUppercase.js'),
	    'passwordReusePrevention'       : require(__dirname + '/plugins/aws/iam/passwordReusePrevention.js'),
	    'rootAccessKeys'                : require(__dirname + '/plugins/aws/iam/rootAccessKeys.js'),
	    'rootAccountInUse'              : require(__dirname + '/plugins/aws/iam/rootAccountInUse.js'),
	    'rootMfaEnabled'                : require(__dirname + '/plugins/aws/iam/rootMfaEnabled.js'),
	    'sshKeysRotated'                : require(__dirname + '/plugins/aws/iam/sshKeysRotated.js'),
	    'usersMfaEnabled'               : require(__dirname + '/plugins/aws/iam/usersMfaEnabled.js'),
	    'usersPasswordLastUsed'         : require(__dirname + '/plugins/aws/iam/usersPasswordLastUsed.js'),
	    'kinesisEncrypted'              : require(__dirname + '/plugins/aws/kinesis/kinesisEncrypted.js'),
	    'firehoseEncrypted'             : require(__dirname + '/plugins/aws/firehose/firehoseEncrypted.js'),
	    'kmsKeyRotation'                : require(__dirname + '/plugins/aws/kms/kmsKeyRotation.js'),
	    'kmsScheduledDeletion'          : require(__dirname + '/plugins/aws/kms/kmsScheduledDeletion.js'),
	    'kmsKeyPolicy'                  : require(__dirname + '/plugins/aws/kms/kmsKeyPolicy.js'),
	    'kmsDefaultKeyUsage'            : require(__dirname + '/plugins/aws/kms/kmsDefaultKeyUsage.js'),

	    'rdsAutomatedBackups'           : require(__dirname + '/plugins/aws/rds/rdsAutomatedBackups.js'),
	    'rdsEncryptionEnabled'          : require(__dirname + '/plugins/aws/rds/rdsEncryptionEnabled.js'),
	    'rdsPubliclyAccessible'         : require(__dirname + '/plugins/aws/rds/rdsPubliclyAccessible.js'),
	    'rdsRestorable'                 : require(__dirname + '/plugins/aws/rds/rdsRestorable.js'),
	    'rdsMultiAz'                    : require(__dirname + '/plugins/aws/rds/rdsMultiAz.js'),

	    'domainAutoRenew'               : require(__dirname + '/plugins/aws/route53/domainAutoRenew.js'),
	    'domainExpiry'                  : require(__dirname + '/plugins/aws/route53/domainExpiry.js'),
	    'domainTransferLock'            : require(__dirname + '/plugins/aws/route53/domainTransferLock.js'),

	    'bucketAllUsersPolicy'          : require(__dirname + '/plugins/aws/s3/bucketAllUsersPolicy.js'),
	    'bucketAllUsersAcl'             : require(__dirname + '/plugins/aws/s3/bucketAllUsersAcl.js'),
	    'bucketVersioning'              : require(__dirname + '/plugins/aws/s3/bucketVersioning.js'),
	    'bucketLogging'                 : require(__dirname + '/plugins/aws/s3/bucketLogging.js'),

	    'notebookDataEncrypted'         : require(__dirname + '/plugins/aws/sagemaker/notebookDataEncrypted.js'),
	    'notebookDirectInternetAccess'  : require(__dirname + '/plugins/aws/sagemaker/notebookDirectInternetAccess.js'),

	    'dkimEnabled'                   : require(__dirname + '/plugins/aws/ses/dkimEnabled.js'),

	    'topicPolicies'                 : require(__dirname + '/plugins/aws/sns/topicPolicies.js'),
	    'sqsCrossAccount'               : require(__dirname + '/plugins/aws/sqs/sqsCrossAccount.js'),
	    'sqsEncrypted'                  : require(__dirname + '/plugins/aws/sqs/sqsEncrypted.js'),

	    'ssmEncryptedParameters'        : require(__dirname + '/plugins/aws/ssm/ssmEncryptedParameters.js'),

	    'lambdaOldRuntimes'             : require(__dirname + '/plugins/aws/lambda/lambdaOldRuntimes.js'),

	    'monitoringMetrics'             : require(__dirname + '/plugins/aws/cloudwatchlogs/monitoringMetrics.js'),

	    'redshiftEncryptionEnabled'     : require(__dirname + '/plugins/aws/redshift/redshiftEncryptionEnabled.js'),
	    'redshiftPubliclyAccessible'    : require(__dirname + '/plugins/aws/redshift/redshiftPubliclyAccessible.js')
	}
};
