import os
import shutil

from . import processDirectory

def renameDefaultCSV(root, file, logger = None, force = False):

    logger.debug('Checking for ".default" extension on file: %s' % file)
    # Determine if the file is a default CSV
    if file[-8:] == ".default":
        logger.debug('File has extension .default, checking if it already exists...')
        # Make sure the file does not already exist
        fname = root + os.sep + file[0:-8]

        if os.path.isfile( fname ) == False:
            logger.debug('File does not exist..')

            # Log that we are copying the file
            if logger:
                logger.info( 'msg="Renaming default CSV file", src="%s", dest="%s"' % ( (root + os.sep + file), fname) )

            # Copy the file
            shutil.copyfile( root + os.sep + file, fname)
        else:
            logger.debug('File already exists, skipping...')
def deployDefaultLookupFiles( app_dir, logger = None ):
    processDirectory( os.path.join(app_dir, "lookups"), renameDefaultCSV, logger, False )

