import json
import requests
import logging
import os
from cloudant import Cloudant
from cloudant.document import Document
from logger import logger

USER_DB = 'users'
ACL_DB = 'acls'

class CloudantDB:

    def __init__(self):

        self.database = None
        self.acl_db = None

        # try to open the db, if not, create it...
        try:
            self.vcap = json.loads(os.getenv("VCAP_SERVICES"))['cloudantNoSQLDB']
            self.cl_username = self.vcap[0]['credentials']['username']
            self.cl_password = self.vcap[0]['credentials']['password']
            self.url = self.vcap[0]['credentials']['url']
            self.auth = (self.cl_username, self.cl_password)
            self.client = Cloudant(self.cl_username, self.cl_password, url=self.url)
            self.client.connect()
            self.database = self.client[USER_DB]
            self.acl_db =  self.client[ACL_DB]

            logger.info('Starting cloudant db at %s' % self.url)

        except:
            logger.error('Unable to load database...')


    def create_db(self):
        self.database = self.client.create_database(USER_DB)

        if self.database.exists():
            return None, False

        return 'Unable to create %s' % USER_DB, True

    def get_all_documents(self):
        documents = []

        for document in self.database:
            documents.append(document)

        if not documents:
            logger.error('Unable to load documents...')
            return None, True

        return {'documents' : documents}, False

    def get_all_acl_db(self):
        documents = []

        for document in self.acl_db:
            documents.append(document)

        if not documents:
            logger.error('Unable to load documents...')
            return None, True

        return {'documents' : documents}, False

    def delete_db(self):
        if self.database.exists():
            self.client.delete_database(USER_DB)

    def insert_document(self, key, data):

        # First retrieve the document
        document, err = self.get_document(key)

        if err:
            logger.info('Document not found, will create it with key=%s' % key)
            return self.create_document(data)

        # Update the document content
        # This can be done as you would any other dictionary
        for key in data:
            try:
                document[key] = data[key]
            except:
                logger.warning('Key %s missing in document %s' % (key, document))

        # You must save the document in order to update it on the database
        document.save()

        logger.info('Success, document id=%s, new rev=%s' % (document['_id'], document['_rev']))
        return '{"_id"="%s", "_rev":"%s"}' % (document['_id'], document['_rev']), False

    def create_document(self, data):

        if '_id' not in data:
            logger.error('No "_id" field in document')
            return 'No "_id" field in document', True

        document = self.database.create_document(data)

        if document.exists():
            return document['_id'], False

        logger.error('Failed to create document %s' % data)
        return 'Failed to create document', True


    def create_report_metadata(self, data):

        if '_id' not in data:
            logger.error('No "_id" field in document')
            return 'No "_id" field in document', True

        document = self.acl_db.create_document(data)

        if document.exists():
            return document['_id'], False

        logger.error('Failed to create document %s' % data)
        return 'Failed to create document', True

    def get_document(self, key):

        try:
            document = self.database[key]
        except:
            logger.error('Failed to retrieve document with key=%s' % key)
            return 'Failed to retrieve document with key=%s' % key, True

        logger.info('Got document %s' % document)
        return document, False

    def get_report_metadata(self, key):

        try:
            document = self.acl_db[key]
        except:
            logger.error('Failed to retrieve document with key=%s' % key)
            return 'Failed to retrieve document with key=%s' % key, True

        logger.info('Got document %s' % document)
        return document, False

    def update_document(self, key, data):

        # First retrieve the document
        document, err = self.get_document(key)

        if err:
            logger.error('Failed to update document with key=%s' % key)
            return 'Failed to update document with key=%s' % key, True

        # Update the document content
        # This can be done as you would any other dictionary
        for key in data:
            try:
                document[key] = data[key]
            except:
                logger.warning('Key %s missing in document %s' % (key, document))

        # You must save the document in order to update it on the database
        document.save()

        logger.info('Success, document id=%s, new rev=%s' % (document['_id'], document['_rev']))
        return '{"_id"="%s", "_rev":"%s"}' % (document['_id'], document['_rev']), False

    def delete_document(self, key):

        # First retrieve the document
        document, err = self.get_document(key)

        if err:
            logger.error('Failed to delete document with key=%s' % key)
            return 'Failed to delete document with key=%s' % key, True

        document.delete()

        logger.info('Success, deleted document key=%s' % key)
        return 'Success, deleted document key=%s' % key, False