#Not Production ready - Refer the Read Me file
import json, os, re, base64, sys, secrets
import GetQuickSightResponse

def lambda_handler(event, context):
    try:
        #This lambda function along with APIGateway is being used to mimic embedding QuickSight dashboard into a static web page.
        #When mode is passed in as static or when not specified, this function returns a static single page HTML.
        #When mode is set to getDashboardList or getUrl, QuickSight APIs are called to get the list of dashboards or embed url 
        #and this is returned the static html page that made this request.
        mode='static'
        response={} 
        if event['queryStringParameters'] is None:
            mode='static'
        elif 'mode' in event['queryStringParameters'].keys():
            if event['queryStringParameters']['mode'] in ['static','getUrl','getDashboardList']:
                mode=event['queryStringParameters']['mode']
            else:
                mode='unsupportedValue'
        
        
        #If mode is static, get the api gateway url from event. 
        #In a truly static use case (like an html page getting served out of S3, S3+CloudFront),this url can be hard coded in the html file
        #Deriving this from event and replacing in html file at run time to avoid having to come back to lambda 
        #to specify the api gateway url while you are building this sample in your environment.
        if event['headers'] is None or event['requestContext'] is None:
            apiGatewayUrl = 'ApiGatewayUrlIsNotDerivableWhileTestingFromApiGateway'
            allowedDomain = 'http://localhost'
        else:
            apiGatewayUrl = 'https://' + event['headers']['Host']+event['requestContext']['path']
            allowedDomain = 'https://'+event['headers']['Host']

        if mode == 'static':
            htmlFile = open('content/embed-sample.html', 'r')
    
            #Read contents of sample html file
            htmlContent = htmlFile.read()
        
            #Read logo file in base64 format
            logoFile = open('content/Logo.png','rb')
            logoContent = base64.b64encode(logoFile.read())
        
            #Read in the environment variables
            cognitoDomainUrl = os.environ['CognitoDomainUrl']
            cognitoClientId = os.environ['CognitoClientId']
            
            #QDisplaySelection : Valid values - ShowQ and HideQ
            #Determines whether to include an embedded Q bar. This should be enabled only if your account has Q turned on.
            #Additionally, you will have to allow list https://<region>.quicksight.aws.amazon.com in QuickSight management panel under Domains and Embedding section
            #Also, make sure that you have shared at least one Q topic with the user / relevant EmbeddedDemoReaders group.
            #Not specifying qDisplaySelection variable is equivalent to setting it's value to HideQ.
            if 'QDisplaySelection' in os.environ:
                qDisplaySelection = os.environ['QDisplaySelection']
                
                #QMode : Valid values - GenerativeQnA and Legacy
                #Not specifying QMode defaults to GenerativeQnA.
                #QMode is applicable only when QDisplaySelection is set to ShowQ.
                if qDisplaySelection == 'ShowQ':
                    if 'QMode' in os.environ:
                        qMode = os.environ['QMode']
                    else:
                        qMode = 'GenerativeQnA'
                else:
                    qMode = 'NoQMode'
            else:
                qDisplaySelection = 'HideQ'
                qMode = 'NoQMode'
                
            
            scriptNonce = secrets.token_urlsafe();
            
            #Replace place holders.
            #logoContent when cast to str is in format b'content'.
            #Array notation is used to extract just the content.
            htmlContent = re.sub('<LogoFileBase64>', str(logoContent)[2:-1], htmlContent)
            htmlContent = re.sub('<apiGatewayUrl>', apiGatewayUrl, htmlContent)
            htmlContent = re.sub('<cognitoDomainUrl>', cognitoDomainUrl, htmlContent)
            htmlContent = re.sub('<cognitoClientId>', cognitoClientId, htmlContent)
            htmlContent = re.sub('<qDisplaySelection>', qDisplaySelection, htmlContent)
            htmlContent = re.sub('<qMode>', qMode, htmlContent)
            htmlContent = re.sub('<ScriptNonce>', scriptNonce, htmlContent)
            
            #Return HTML. 
            return {'statusCode':200,
                'headers': {
                    "Content-Security-Policy":"default-src 'self' ;\
                                    upgrade-insecure-requests;\
                                    script-src 'self' 'nonce-" + scriptNonce + "' \
                                    https://unpkg.com/amazon-quicksight-embedding-sdk@2.7.0/dist/quicksight-embedding-js-sdk.min.js\
                                    https://code.jquery.com/jquery-3.5.1.min.js\
                                    https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js;\
                                    style-src  'unsafe-inline' \
                                    https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css;\
                                    child-src 'self' blob: https://*.quicksight.aws.amazon.com/ ;\
                                    img-src 'self' data: ;\
                                    base-uri 'self';\
                                    object-src 'none';\
                                    frame-ancestors 'self' ",
                    "Content-Type":"text/html"
                    
                },
                'body':htmlContent
                }
                
        elif mode in [ 'getUrl', 'getDashboardList' ]:
            
            response = GetQuickSightResponse.handler(event, context, mode, allowedDomain)
           
            #Return response from Quicksight.
            #Access-Control-Allow-Origin doesn't come into play in this sample as origin is the API Gateway url itself.
            #When using the static mode wherein initial static HTML is loaded from a different domain, this header becomes relevant.
            #You should change to the specific origin domain in that scenario to avoid CORS error.  
            return {'statusCode':200,
                    'headers': {"Access-Control-Allow-Origin": "-",
                                "Content-Type":"text/plain"},
                    'body':json.dumps(response)
                    } 
        else: #unsupported mode
            #Return error along with list of valid mode values.
            return {'statusCode':400,
                    'headers': {"Access-Control-Allow-Origin": "-",
                                "Content-Type":"text/plain"},
                    'body':json.dumps('Error: unsupported mode used. Valid values are static, getUrl, getDashboardList')
                    } 
    except Exception as e: #catch all
        return {'statusCode':400,
                'headers': {"Access-Control-Allow-Origin": "-",
                            "Content-Type":"text/plain"},
                'body':json.dumps('Error: ' + str(e))
                }     
