def is_spam(event, context):
    ses_notification = event['Records'][0]['ses']
    message_id = ses_notification['mail']['messageId']
    receipt = ses_notification['receipt']

    print('Processing message:', message_id)
    is_spam = (receipt['spamVerdict']['status'] == 'FAIL' or
            receipt['virusVerdict']['status'] == 'FAIL')

    if is_spam:
        print('SPAM message:', message_id)
    else:
        print('HAM message:', message_id)

    return is_spam


def spam_filter(event, context):
    '''Reject all spam emails'''
    print('Starting - inbound-ses-spam-filter')
    if is_spam(event, context):
        return {'disposition': 'stop_rule'}


def spam_trap_filter(event, context):
    '''Collect All Spam Emails'''
    print('Starting - inbound-ses-spam-trap-filter')
    if not is_spam(event, context):
        return {'disposition': 'stop_rule'}

