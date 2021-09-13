#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from cofensevision_consts import *
import requests
import json
from ast import literal_eval
from bs4 import BeautifulSoup


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

class CofenseVisionConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CofenseVisionConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        # Starts authentication request. Successful authentication implies successful test connectivity.

        self.save_progress("Sending authentication request...")
        ret_val, response = self.vision_auth_make_rest_call(action_result)
        # vision API call has no headers, params, data, etc. anymore

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test connectivity failed.")
            return action_result.get_status()

        # Return success.
        self.save_progress("Test connectivity passed.")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def vision_auth_make_rest_call(self, action_result, headers=None, params=None, method='post'):

        endpoint = self._base_url + '/uaa/oauth/token'

        config = self.get_config()
        co_username = config.get("Account Username")
        co_password = config.get("Account Password")

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create header and data payload.
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'grant_type': 'client_credentials'}

        self.save_progress("Vision authentication: executing REST call to authentication endpoint.")

        try:
            r = request_func(endpoint, auth=(co_username, co_password), data=data, headers=headers, verify=config.get('verify_server_cert', False), params=params)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error connecting to server. Details: {0}".format(str(e))), resp_json)

        return self.vision_auth_process_response(r, action_result)

    def vision_auth_process_response(self, r, action_result):
        self.save_progress("Vision authentication: Processing Response")
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Takes API response and formats it as JSON.
        response_json = r.json()

        # For Cofense API call, successful authentication means there is a bearer token.
        token = response_json.get("access_token")

        # Token is saved in Phantom and can be retrieved across actions.
        self._state['token'] = str(token)
        self.save_state(self._state)

        if token:
            self.save_progress("Vision authentication: Processing...token retrieved.")
            return RetVal(phantom.APP_SUCCESS, token)
        else:
            self.save_progress("Vision authentication: Processing...failed to retrieve token.")
            message = "Vision auth failed. Please confirm username and password."
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _handle_check_inboxes(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))





        ############
        # API CALL 1
        ############

        # Step 1: obtain token and set token in header. Define data dictionary to pass to API call.

        token = self._state['token']
        self.save_progress("token is {}".format(token))
        headers = {}
        headers["Authorization"] = "Bearer " + token

        data = {}

        # Optional values.
        # There are three paramter types:
        # 1. strings. These are directly received.
        # 2. arrays. These arrive in comma-separated form and are split to individual strings before being put in array.
        # 3. JSON objects. These arrive as strings and are safely converted to dictionary format.

        if param.get('recipient'):
            data['recipientAddress'] = param['recipient']
        if param.get('internetmessageid'):
            data['internetMessageId'] = param['internetmessageid']
        if param.get('receivedafterdate'):
            data['receivedAfterDate'] = param.get('receivedafterdate')
        if param.get('receivedbeforedate'):
            data['receivedBeforeDate'] = param.get('receivedbeforedate')
        if param.get('url'):
            data['url'] = param.get('url')
        if param.get('subjects'):
            subjects = param.get('subjects')
            data['subjects'] = [subject.strip() for subject in subjects.split(',')]
        if param.get('senders'):
            senders = param.get('senders')
            data['senders'] = [sender.strip() for sender in senders.split(',')]
        if param.get('attachmentnames'):
            attachment_names = param.get('attachment_names')
            data['attachmentNames'] = [name.strip() for name in attachment_names.split(',')]
        if param.get('attachmentmimetypes'):
            mimetypes = param.get('attachmentmimetypes')
            data['attachmentMimeTypes'] = [type.strip() for type in mimetypes.split(',')]
        if param.get('attachmentexcludemimetypes'):
            excludetypes = param.get('attachmentexcludemimetypes')
            data['attachmentExcludeMimeTypes'] = [type.strip() for type in excludetypes.split(',')]
        if param.get('attachmenthashcriteria'):
            object = param.get('attachmenthashcriteria')
            data['attachmentHashCriteria'] = literal_eval(object)
        if param.get('domaincriteria'):
            object = param.get('domaincriteria')
            data['domainCriteria'] = literal_eval(object)

        self.save_progress("param is {}".format(param))
        self.save_progress("data is {}".format(data))

        # Step 2: first API call creates new search. Error handling is included in two ways.

        self.save_progress("Making first API call.")

        ret_val, response = self._make_rest_call(ENDPOINT_CREATE_NEW_SEARCH, action_result, json=data, headers=headers, method='post')
        msg = action_result.get_message()

        # Reauth with plain JSON_response function.
        if "invalid_token" in msg:
            self.save_progress("Bearer token expired. Executing new authentication request.")
            ret_val, response = self.vision_auth_make_rest_call(action_result)
            token = self._state['token']
            headers["Authorization"] = "Bearer " + token
            ret_val, response = self._make_rest_call(
                ENDPOINT_CREATE_NEW_SEARCH, action_result, json=data, headers=headers, method='post'
            )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()
            pass

        # Step 3: save the response as action_results. Do not save to summary now.

        self.save_progress("First API call is successful.")
        self.save_progress("First API response is {}".format(response))
        # action_result.add_data(response)



      

        ############
        # API CALL 2
        ############

        # Step 4: save ID and create new endpoint. This is what we need for the second API call.

        search_id = str(response['id'])
        ENDPOINT_1 = ENDPOINT_GET_SEARCH_RESULTS.format(search_id)

        # Step 5: make second API call to obtain search results from new search. Error handling is included.

        self.save_progress("Making second API call.")

        ret_val, response = self._make_rest_call(ENDPOINT_1, action_result, headers=headers)

        msg = action_result.get_message()

        # Reauthenticate.
        if 'invalid_token' in msg:
            self.save_progress("Bearer token expired. Executing new authentication request.")
            ret_val, response = self.vision_auth_make_rest_call(action_result)
            token = self._state['token']
            headers["Authorization"] = "Bearer " + token
            ret_val, response = self._make_rest_call(ENDPOINT_1, action_result, headers=headers)

        # If other error occurs.
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()
            pass

        # Step 6: save API response as action_result data. Save subset of data in action_result.summary section.

        self.save_progress("Second API call is successful.")
        self.save_progress("Second API response is {}".format(response))
        action_result.add_data(response)

        pairs = {}

        num_messages = len(response['messages'])
        if num_messages > 0:
            messages = response['messages']
            for message in messages:
                id = message['internetMessageId']
                recipients = [recipient['address'] for recipient in message['recipients']]
                pairs[id] = [recipients]
        action_result.add_data(pairs)
        summary = action_result.update_summary({"total messages": num_messages})





        ############
        # FINAL STEP
        ############

        # Step 7: return appropriate status for action run.

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_add_to_quarantine(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))





        ############
        # API CALL 1
        ############

        # Step 1: obtain token and set token in header. Define data dictionary to pass to API call.

        token = self._state['token']
        self.save_progress("token is {}".format(token))
        headers = {}
        headers["Authorization"] = "Bearer " + token

        # Builds list of JSON objects, each object representing a recipient/messageid combination.

        recipient_list = param['recipientaddress']
        messageid_list = param['internetmessageid']

        emails_list = []

        for recipient, id in zip(recipient_list, messageid_list):
            email = {}
            email['recipientAddress'] = recipient
            email['internetMessageId'] = id
            emails_list.append(email)

        # Add email JSON object to data payload.

        data = {}
        data['quarantineEmails'] = emails_list

        # Step 2: first API call creates new quarantine job.

        self.save_progress("Making first API call.")

        self.save_progress("data is {}".format(data))
        self.save_progress("headers is {}".format(headers))

        ret_val, response = self._make_rest_call(ENDPOINT_ADD_TO_QUARANTINE, action_result, json=data, headers=headers, method='post')

        msg = action_result.get_message()

        # Reauthenticate.
        if 'invalid_token' in msg:
            self.save_progress("Bearer token expired. Executing new authentication request.")
            ret_val, response = self.vision_auth_make_rest_call(action_result)
            token = self._state['token']
            headers["Authorization"] = "Bearer " + token
            ret_val, response = self._make_rest_call(ENDPOINT_ADD_TO_QUARANTINE, action_result, json=data, headers=headers, method='post')

        # If other error occurs.
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()
            pass

        # Step 3: save API response as action_result data. Save subset of data in action_result.summary section.

        self.save_progress("First API call is successful.")
        self.save_progress("First API response is {}".format(response))
        action_result.add_data(response)

        quarantine_job_id = response['id']
        status = response['quarantineJobRuns'][0]['status']
        job_run_type = response['quarantineJobRuns'][0]['jobRunType']
        summary = action_result.update_summary({"quarantineJobId": quarantine_job_id, \
                                                "status": status, \
                                                "jobRunType": job_run_type})





        ############
        # FINAL STEP
        ############

        # Step 4: return appropriate status for action run.

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_remove_from_quarantine(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))





        ############
        # API CALL 1
        ############

        # Step 1: obtain token and set token in header. Define data dictionary to pass to API call.

        token = self._state['token']
        self.save_progress("token is {}".format(token))
        headers = {}
        headers["Authorization"] = "Bearer " + token

        job_id = param['jobid']
        ENDPOINT_1 = ENDPOINT_STOP_QUARANTINE.format(job_id)

        # Step 2: first API call creates new quarantine job.

        self.save_progress("Making first API call.")

        self.save_progress("headers is {}".format(headers))
        self.save_progress(ENDPOINT_1)

        ret_val, response = self._make_rest_call(ENDPOINT_1, action_result, headers=headers, method='put')

        msg = action_result.get_message()

        # Reauthenticate.
        if 'invalid_token' in msg:
            self.save_progress("Bearer token expired. Executing new authentication request.")
            ret_val, response = self.vision_auth_make_rest_call(action_result)
            token = self._state['token']
            headers["Authorization"] = "Bearer " + token
            ret_val, response = self._make_rest_call(ENDPOINT_1, action_result, headers=headers, method='put')

        # If other error occurs.
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()
            pass

        # Step 3: save API response as action_result data. Save subset of data in action_result.summary section.

        self.save_progress("First API call is successful.")
        self.save_progress("First API response is {}".format(response))
        action_result.add_data(response)
        stop_requested = response['stopRequested']
        summary = action_result.update_summary({"stopRequested": stop_requested})





        ############
        # API CALL 2
        ############

        # Step 4: save ID and create new endpoint. This is what we need for the second API call.

        ENDPOINT_2 = ENDPOINT_RESTORE_FROM_QUARANTINE.format(job_id)

        # Step 5: make second API call to obtain search results from new search. Error handling is included.

        self.save_progress("Making second API call.")

        ret_val, response = self._make_rest_call(ENDPOINT_2, action_result, headers=headers, method='put')

        msg = action_result.get_message()

        # Reauthenticate.
        if 'invalid_token' in msg:
            self.save_progress("Bearer token expired. Executing new authentication request.")
            ret_val, response = self.vision_auth_make_rest_call(action_result)
            token = self._state['token']
            headers["Authorization"] = "Bearer " + token
            ret_val, response = self._make_rest_call(ENDPOINT_2, action_result, headers=headers, method='put')

        # If other error occurs.
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()
            pass

        # Step 6: save API response as action_result data. Save subset of data in action_result.summary section.

        self.save_progress("Second API call is successful.")
        self.save_progress("Second API response is {}".format(response))
        action_result.add_data(response)

        if not response:
            status = "success"
        summary = action_result.update_summary({"status": status})





        ############
        # FINAL STEP
        ############

        # Step 4: return appropriate status for action run.

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")


    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'check_inboxes':
            ret_val = self._handle_check_inboxes(param)

        elif action_id == 'add_to_quarantine':
            ret_val = self._handle_add_to_quarantine(param)

        elif action_id == 'remove_from_quarantine':
            ret_val = self._handle_remove_from_quarantine(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('Server IP/Hostname')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CofenseVisionConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print(("Unable to get session id from the platform. Error: " + str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print((json.dumps(in_json, indent=4)))

        connector = CofenseVisionConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print((json.dumps(json.loads(ret_val), indent=4)))

    exit(0)


if __name__ == '__main__':
    main()
