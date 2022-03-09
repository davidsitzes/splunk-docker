import os

def get_session_key(session_key=None, thrown_exception=True):

    # Try to get the session key if not provided
    if session_key is None:
        import splunk
        session_key, sessionSource = splunk.getSessionKey(return_source=True)

    # Do not continue if we could not get a session key and the caller wants us to thrown an exception
    if session_key is None and thrown_exception:
        raise Exception("Could not obtain a session key")

    # Return the session key
    return session_key

def processDirectory( basedir, fn, logger = None, force = False ):

    # Iterate through each directory and run the given function
    for root, dirs, files in os.walk(basedir):
        logger.debug('Current root: %s, Current Dirs: %s, Current Files: %s' % (root,dirs,files))
        for file in files:
            logger.debug('Working with file: %s' % (file))
            fn(root, file, logger, force)
