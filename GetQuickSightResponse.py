import sys
#Python-jose can be used to verify the openIdToken locally if needed.
if './optionalPackages' not in sys.path:
    sys.path.append('./optionalPackages')
    
import json, os, boto3, base64, time,re,urllib3, math
from jose import jwk, jwt


def handler(event, context, mode, allowedDomain):
    awsAccountId = roleArn = roleName = userName = email = groupName = dashboardRegion = identityRegion = quickSight = quickSightIdentity = \
    webIdentitySubject = webIdentityProvider = authEvalMode = region = expiryTs = urlType = openIdToken = qMode = None

    #Function to check validity of the token
    def checkTokenValidity():
        nonlocal authEvalMode, roleArn, userName, openIdToken, webIdentitySubject, webIdentityProvider, region, userName, email, expiryTs
        try:
            stage = 'Before parsing payload'
            #Replace - and _ chars, if present, with base64 equivalents
            base64OpenIdToken = openIdToken.replace('-','+').replace('_','/')
            
            base64Payload = base64OpenIdToken.split('.')[1]
            #Pad with = char to make the whole string length divisible by 4
            payload = json.loads(base64.b64decode(base64Payload+ "="*((4 - len(base64Payload)%4) % 4) ))
            
            userName = payload['cognito:username']
            email = payload['email']
            webIdentitySubject = payload['sub']
            webIdentityProvider = payload['iss']
            expiryTs = payload['exp']
            
            stage = 'After parsing payload'
            #In default flow, we will leverage STS assume_role_with_web_identity to verify the token.
            #We are not using the returned credentials to really do anything with this role. Rather, just relying in a successful call to know that token is valid.
            #Token can be verified locally as well. In python, we can leverage python-jose library for this. Other languages might offer similar libraries as well.
            #To run in local verification mode, two additional env variables need to be added.
            # AuthEvalMode          : Local
            # CognitoUserPoolId     : <User pool id from Cognito>
            #When configured in this mode, STS assume role API won't be called. 
            #You can verify that the flow is not using STS by updating the trust relationship of the role in IAM (add a suffix to the Federated Principal arn) 
            #or by deleting the Identity provider mapping in IAM altogether.
            if authEvalMode == 'STS':
                stage = 'In STS block'
                sts = boto3.client('sts')
                assumedRole = sts.assume_role_with_web_identity(
                    RoleArn = roleArn,
                    RoleSessionName = userName,
                    WebIdentityToken = openIdToken
                )
                return True
            else:
                stage = 'In Local block'
                base64HeaderAndPayload = base64OpenIdToken.rsplit('.',1)[0]
                base64Signature = base64OpenIdToken.split('.')[2]
                
                base64Header = base64OpenIdToken.split('.')[0]
                header = json.loads(base64.b64decode(base64Header + "="*((4 - len(base64Header)%4) % 4) ))

                http = urllib3.PoolManager()
                
                if 'CognitoUserPoolId' not in os.environ:
                    raise Exception('CognitoUserPoolId env var is required with Local AuthEvalMode. Add it to Lambda env variables section.')
                    
                cognitoUrl = 'https://cognito-idp.'+region+'.amazonaws.com/'+os.environ['CognitoUserPoolId']
                stage = 'After creating cognitoUrl'
                
                #Ensure that the token was issued by same cognito user pool that we are using and that it hasn't expired yet.
                if cognitoUrl == webIdentityProvider and expiryTs > time.time():
                    stage = 'After checking provider and expiry'
                    
                    #Get the public key from cognito
                    keys=json.loads(http.request('GET', cognitoUrl+'/.well-known/jwks.json').data)['keys']
                    for key in keys:
                        if key['kid'] == header['kid'] :
                            public_key = jwk.construct(key)
                            #If the signature decrypted with public key matches the header and payload, token is valid.
                            if public_key.verify( base64HeaderAndPayload.encode('utf-8'), base64.b64decode(base64Signature + "="*((4 - len(base64Signature)%4) % 4) ) ):
                                return True
            
                raise Exception('Invalid token')
            
        except Exception as e:
            raise Exception('checkTokenValidity function:'+stage+': '+str(e))

    #Function that derives the identity region of your QuickSight account.
    def getIdentityRegion():
        nonlocal awsAccountId, dashboardRegion, quickSight
        try:
            quickSight.describe_user(
                AwsAccountId = awsAccountId,
                Namespace = 'default',
                UserName = 'non-existent-user')
                
        except quickSight.exceptions.AccessDeniedException as e:
            #QuickSight manages all users and groups in the identity region of the account.
            #This can be different from the dashboard region provided as input to lambda.
            #Calls to APIs that deal with identity can be made against identity region only.
            #We made the call against dashboard region first. 
            #Since that didn't work, we will extract the identity region from the error message that is returned
            if str(e).find('but your identity region is') > -1 :
                identityRegion = str(e).split('but your identity region is ')[1].split('.')[0]
                return identityRegion
            raise Exception('Lambda GetQuickSightResponse.getIdentityRegion function:'+str(e))
            
        except quickSight.exceptions.ResourceNotFoundException as e:
            #Call went through which means the dashboardRegion we used is your identity region as well.
            identityRegion = dashboardRegion
            return identityRegion
            
        except Exception as e:
            raise Exception('Lambda GetQuickSightResponse.getIdentityRegion function:'+str(e))
       
        
    
    #Get list of dashboards that user has access to. If user doesn't exist, trigger creation of user, group and group membership.    
    def getDashboardList(recursionDepth):
        nonlocal awsAccountId, roleArn, roleName, userName, email, dashboardRegion, identityRegion, quickSight, quickSightIdentity
        try:
            #Safeguard - If recursion depth is greater than 2, raise exception
            if recursionDepth > 2:
                raise Exception('getDashboardList: Deeper recursion than expected')
            recursionDepth += 1
            
            #Check if the user exists. If not, add the user, group and group membership.
            #It is recommended that you pre-register users whenever possible so that you don't have to make an extra API call each time.
            #If that is not possible, you can use this approach for Just In Time provisioning.
            quickSightIdentity.describe_user(
                            AwsAccountId = awsAccountId,
                            Namespace = 'default',
                            UserName = roleName + '/' + userName)
                
            #Get list of dashboards that that the user has permission to access.
            response = quickSight.search_dashboards(
                            AwsAccountId = awsAccountId,
                            Filters = [
                                        {
                                            'Operator': 'StringEquals',
                                            'Name': 'QUICKSIGHT_USER',
                                            'Value': 'arn:aws:quicksight:' + identityRegion + ':' + awsAccountId + ':user/default/' + roleName + '/' + userName
                                        }
                                    ]
                        )
                        
            #Repack the response to include just the dashboard names and ids
            repackedResponse={}
            repackedResponse['openIdToken']=openIdToken
            repackedResponse['expiryTs']=expiryTs
            repackedResponse['Dashboards']=[]
            for dashboard in response['DashboardSummaryList']:
                dashboardRepacked={}
                dashboardRepacked['Name']=dashboard['Name']
                dashboardRepacked['DashboardId']=dashboard['DashboardId']
                repackedResponse['Dashboards'].append(dashboardRepacked)
            
            #Return the dashboard list to calling function.
            return repackedResponse
            
        except quickSight.exceptions.ResourceNotFoundException as e:
            #Register the user since user does not exist in QuickSight
            registerUser()
            #Add the user to EmbeddedDemoReaders group    
            createGroupMembership(1)
            #Make a recursive call. Dashboard list returned from this call is returned to handler function.
            return getDashboardList(recursionDepth)
            
        except Exception as e:
            raise Exception('Lambda GetQuickSightResponse.getDashboardList function:'+str(e))
    
    
    
    def registerUser():
        nonlocal awsAccountId, roleArn, userName, email, quickSightIdentity, webIdentitySubject, webIdentityProvider
        try:
    
            #Register the user
            #When using web identity, it is a good practice to set the following optional parameters - ExternalLoginFederationProviderType, CustomFederationProviderUrl,ExternalLoginId
            #This way, if the role has permissions to run get-dashboard-embed-url, we can ensure that user identity is not spoofed by passing in an incorrect Role session name.
            #In this code sample, the role we use hasn't been granted any permissions at all. Also, we are using the new generate-embed-url-for-registered-user API from lambda layer to generate the urls.
            quickSightIdentity.register_user(
                AwsAccountId = awsAccountId,
                Namespace = 'default',
                IdentityType ='IAM',
                IamArn = roleArn,
                SessionName = userName,
                Email = email,
                UserRole ='READER',
                ExternalLoginFederationProviderType = 'CUSTOM_OIDC',
                CustomFederationProviderUrl = webIdentityProvider,
                ExternalLoginId = webIdentitySubject
                )
    
        except Exception as e:
            raise Exception('Lambda GetQuickSightResponse.registerUser function:'+str(e))
            
    
    
    #Add user to embedded reader group. Create the group if it doesn't already exist.
    def createGroupMembership(recursionDepth):
        nonlocal awsAccountId, roleName, userName, groupName, quickSightIdentity
        try:
            #Safeguard - If recursion depth is greater than 2, raise exception
            if recursionDepth > 2:
                raise Exception('createGroupMembership: Deeper recursion than expected')
            recursionDepth += 1
    
            #Add user to EmbeddedDemoReaders group
            quickSightIdentity.create_group_membership(
                AwsAccountId = awsAccountId,
                Namespace = 'default',
                MemberName = roleName + '/' + userName,
                GroupName = groupName)
                
        except quickSightIdentity.exceptions.ResourceNotFoundException as e:
            #If group is not present in QuickSight, create it.
            quickSightIdentity.create_group(
                AwsAccountId = awsAccountId,
                Namespace = 'default',
                GroupName = groupName)
            #Make a recursive call
            time.sleep(0.5) #adding half second wait just for added safety 
            createGroupMembership(recursionDepth)
            
        except Exception as e:
            raise Exception('Lambda GetQuickSightResponse.createGroupMembership function:'+str(e))
            
            
            
    #Get dynamic embed url        
    def getUrl(recursionDepth):
        nonlocal awsAccountId, quickSight, quickSightIdentity, identityRegion, roleName, userName, expiryTs, urlType, qMode
        try:
            #Safeguard - If recursion depth is greater than 6, raise exception
            if recursionDepth > 6:
                raise Exception('getUrl: Deeper recursion than expected')
            recursionDepth += 1
    
            #Check if the user exists. If not, wait for user to be added from parallel call made to retrieve dashboard list.
            #It is recommended that you pre-register users whenever possible so that you don't have to make an extra API call each time.
            #If that is not possible, you can use this approach for Just In Time provisioning.
            quickSightIdentity.describe_user(
                            AwsAccountId = awsAccountId,
                            Namespace = 'default',
                            UserName = roleName + '/' + userName)
                            
            #Derive session duration from expiryTs.
            #Min value supported by QuickSight is 15 (mins) and max value is 600 (mins)
            #We are setting the Cognito token and javascript cookie expiry at 1 hour. So, will use 1 hour as upper threshold here.
            derivedSessionDuration = math.ceil((expiryTs-time.time())/60)
            
            if derivedSessionDuration < 15:
                adjustedSessionDuration = 15
            elif derivedSessionDuration > 60:
                adjustedSessionDuration = 60
            else:
                adjustedSessionDuration = derivedSessionDuration
            
            repackedResponse = {}
            
            if urlType == 'dashboard':    
                #Generate embed url for dashboard
                #We are using the new generate_embed_url_for_registered_user API to generate the dashboard embed url.
                #Older variant - get_dashboard_embed_url - will continue to be available. However, newer features will be getting added only to the new API.
                response = quickSight.generate_embed_url_for_registered_user(
                                AwsAccountId = awsAccountId,
                                UserArn = 'arn:aws:quicksight:'+ identityRegion + ':' + awsAccountId + ':user/default/' + roleName + '/' + userName,
                                SessionLifetimeInMinutes = adjustedSessionDuration,
                                AllowedDomains = [allowedDomain],
                                ExperienceConfiguration = {'Dashboard':{'InitialDashboardId': 'non-existent-id'}}
                            )
                repackedResponse['DashboardEmbedUrl'] = response['EmbedUrl']
            
            if urlType == 'console':    
                #Generate embed url for console
                #We are using the new generate_embed_url_for_registered_user API to generate the session embed url as well.
                #Older variant - get_session_embed_url - will continue to be available. However, as mentioned above, newer features will be getting added only to the new API.
                response = quickSight.generate_embed_url_for_registered_user(
                                AwsAccountId = awsAccountId,
                                UserArn = 'arn:aws:quicksight:'+ identityRegion + ':' + awsAccountId + ':user/default/' + roleName + '/' + userName,
                                SessionLifetimeInMinutes = adjustedSessionDuration,
                                AllowedDomains = [allowedDomain],
                                ExperienceConfiguration = {'QuickSightConsole':{'InitialPath': '/start/favorites'}}
                            )
                repackedResponse['ConsoleEmbedUrl'] = response['EmbedUrl']

            if urlType == 'q':    
                
                #Generate embed url for Q search bar
                #Since QSearchBar/GenerativeQnA option is fed an empty structure in ExperienceConfiguration, 
                #Q bar will display list of all topics that has been shared with the user.
                #If desired, you can pass in an InitialTopicId to have Q bar open to a specific topic.
                response = quickSight.generate_embed_url_for_registered_user(
                                AwsAccountId = awsAccountId,
                                UserArn = 'arn:aws:quicksight:'+ identityRegion + ':' + awsAccountId + ':user/default/' + roleName + '/' + userName,
                                SessionLifetimeInMinutes = adjustedSessionDuration,
                                AllowedDomains = [allowedDomain],
                                ExperienceConfiguration = {'QSearchBar':{}} if qMode == 'Legacy' else {'GenerativeQnA':{}}
                            )
                repackedResponse['QEmbedUrl'] = response['EmbedUrl']
            
            return repackedResponse
            
        except (quickSight.exceptions.QuickSightUserNotFoundException, quickSight.exceptions.ResourceNotFoundException) as e:
            #If user is not found, wait 2 seconds and try again.
            #Meanwhile, User will get added from the parallel call to retrieve dashboard list flow.
            time.sleep(2)
            return getUrl(recursionDepth)
            
        except Exception as e:
            raise Exception('Lambda GetQuickSightResponse.getUrl function:'+str(e))
    
    #Main logic of Handler     
    try:
        
        #Get AWS Account Id
        awsAccountId = context.invoked_function_arn.split(':')[4]
        region = context.invoked_function_arn.split(':')[3]
        stage = 'After getting account id'
        
        #Read in the environment variables
        dashboardRegion = os.environ['DashboardRegion']
        roleArn = os.environ['RoleArn']
        #Extract role name from arn
        roleName = roleArn.split('/')[1]
        
        #By default, we will use AuthEvalMode of STS wherein we will utilize STS assume_role_with_web_identity to assume a dummy role.
        #STS will allow us to assume the role only if the token is valid.
        if 'AuthEvalMode' in os.environ:
            authEvalMode = os.environ['AuthEvalMode']
        else:
            #default value
            authEvalMode = 'STS'
            
        if 'Suffix' in os.environ:
            suffix = os.environ['Suffix']
        else:
            suffix = ''
        groupName = 'EmbeddedDemoReaders'+suffix
        stage = 'After getting env vars'
        
        #Read in the values passed to Lambda function as query string parameters
        openIdToken = event['queryStringParameters']['openIdToken']
        

        if checkTokenValidity():
            stage = 'After verifying token'
            #Create QuickSight client
            quickSight = boto3.client('quicksight',region_name= dashboardRegion)
            stage = 'After creating QuickSight client'
    
            #Pick identityRegion from environment variable if available or else derive it.
            if 'IdentityRegion' in os.environ:
                identityRegion = os.environ['IdentityRegion']
            else:
                identityRegion = getIdentityRegion()
            stage = 'After deriving QuickSight Identity Region'
            
            quickSightIdentity = boto3.client('quicksight',region_name= identityRegion)
            stage = 'After creating QuickSight client for Identity Region'
            
            if mode == 'getDashboardList':
                stage = 'Before getDashboardList call'
                response = getDashboardList(1)
                stage = 'After getDashboardList call'
                
            else: #mode == 'getUrl'
                stage = 'Before getUrl call'
                urlType = event['queryStringParameters']['urlType']
                if urlType == 'q':
                    qMode = event['queryStringParameters']['qMode']
                response = getUrl(1)
                stage = 'After getUrl call'
        
            return response

            
    except Exception as e:
        raise Exception('Lambda GetQuickSightResponse.handler function:'+stage+': '+str(e))
