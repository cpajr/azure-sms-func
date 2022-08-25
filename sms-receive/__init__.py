import logging
import azure.functions as func
from azure.communication.sms import SmsClient
import json
import os
import re

def validNumber(tel_num):
    '''
    Method to validate that the number is a valid E.164 North American number
    '''
    regex = re.compile(r"^\+1([2-9]\d{2}[2-9]\d{6})$")
    if (regex.search(tel_num)):
        return True
    else:
        return False

def validMsgType(msg_type):
    '''
    Method to validate the predescribed message_type
    '''
    if (msg_type != '1'):
        return False
    else:
        return True

def msg_format(msg_type):
    '''
    Method to return the predescribed message
    '''
    msg_1 = 'ZAGG Customer Svc: For further self help options, please visit https://support.zagg.com'

    if (msg_type == '1'):
        return msg_1

def send_sms(msg_type, tel_num):
    '''
    Method to send SMS Message
    '''
    msg = msg_format(msg_type)
    connection_str = os.environ['AzureCommunications']
    azure_num = os.environ['AzureNumber']
    sms_client = SmsClient.from_connection_string(connection_str, logging_enable=False)

    sms_responses = sms_client.send(from_=azure_num,
                                    to=tel_num,
                                    message=msg,)
    
    sms_response = sms_responses[0]

    if (sms_response.successful):
        logging.info('Message ({}) with ID {} was successfully sent to {}'
            .format(msg_type, sms_response.message_id, sms_response.to))
        return True
    else:
        logging.info('Failed to send message with ID {} to {} with status code {} and error: {}'
            .format(sms_response.message_id,sms_response.to, sms_response.http_status_code, sms_response.error_message))
        return False

def main(req: func.HttpRequest) -> func.HttpResponse:
    #Random logging configuration
    logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    logger.setLevel(logging.WARNING)

    logging.info('Python HTTP trigger function processed a request.')

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(status_code=400)
    else:
        msg_type = req_body.get('msg_type')
        tel_num = req_body.get('tel_num')

        #Deal with invalid Phone Numbers and Message Type
        if (validNumber(tel_num) != True):
            logging.warning('Invalid Number {}'.format(tel_num))
            return func.HttpResponse("Invalid North American E.164 number {}\n".format(tel_num),status_code=400)
        if (validMsgType(msg_type) != True):
            logging.warning('Invalid Message Type {}'.format(msg_type))
            return func.HttpResponse("Invalid Message Type({})\n".format(msg_type),status_code=400)
        
        #Send SMS
        if (send_sms(msg_type, tel_num) != True):
            return func.HttpResponse("Failed to send SMS message",status_code=500)

        logging.info('Successful process, Type ({}) for {}'.format(msg_type, tel_num))
        return func.HttpResponse('Successful',status_code=200)
