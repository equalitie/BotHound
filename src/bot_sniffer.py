"""
BotSniffer

Is the parent of other sniffer classes in BotBanger to inherited from. Each sniffer
classes do prediction based on raw data and a Learn2Ban model. The diffiernce
is in the way they receive the log. For example FileSniffer is getting the 
information from log file, while SimpleLiveSniffer gets it out of zmq subscription
to Banjax

AUTHORS: Vmon (C) August 2013: Initial version
"""
import logging

#Learn to ban modules
from learn2ban.features import *
from learn2ban.features.learn2ban_feature import Learn2BanFeature
from learn2ban.ip_sieve import IPSieve
from learn2ban.train2ban import TrainingSet

from failmodel import FailModel, FailModelException

class BotSniffer(object):
    def __init__(self):
        #Initially we set the classifier equal to null
        self._fail_models = list()
        ## The ip siever:
       	self._ip_sieve = IPSieve()
	self._build_available_feature_list()

    def _build_available_feature_list(self):
        """
        Search all the available feature class and stored them
        in a dictionary indexed by their names
        """
        self._available_features={}
        self._feature_list = list()
        for CurrentFeatureType in Learn2BanFeature.__subclasses__():
            self._available_features[CurrentFeatureType.__name__] = CurrentFeatureType
            #This is wrong we need to update the list when we load the 
            #failmodel and the failModel class should keep a list for 
            #each classifier separately. But till bill adds the used features to
            #the fialmodel's base64 string we stick to this solution, assuming 
            #that all features are used
            self.addFeature(CurrentFeatureType.__name__)
    
    def addFailModel(self, value):
        """
        called by the jail to send the classifier model and the host regex
        to be used by this filter. For now only linear svm is supported. 
        The classifier comes pre-trained.

        INPUT:
            failmodel: only "svm.linear" is supported for now
        """
        try:
            self._fail_models.append(FailModel(value))
        except FailModelException, e:
            logging.error(e)

    def delFailModel(self, index):
        try:
            del self._fail_models[index]
        except IndexError:
            logging.error("Cannot remove fail model. Index %d is not "
						 "valid" % index)
    ### To be implemented
    def addFeature(self, feature_class_name):
        self._feature_list.append(feature_class_name)

    def delFeature(self, feature_class_name):
        try:
            del self[self._feature_list.find(feature_class_name)]

        except IndexError:
            logging.error("Cannot remove %s from feature list." %feature_class_name)

    def _predict_failure(self, ip_feature_db):
        """
        Turn the ip_feature_db into two dimensional array and feed it to
        all classifiers.
        """
        failList = list()
        ip_set = TrainingSet()
        for fail_model in self._fail_models:
            ip_set._normalisation_data = fail_model.getNormalisationData()
            ip_set._normalisation_function = ip_set.normalise_individual
            if ip_set._normalisation_data[TrainingSet.NORMALISATION_TYPE] == 'sparse':
                ip_set._normalisation_function = ip_set.normalise_sparse

            ip_set = ip_set.precook_to_predict(ip_feature_db)
            print ip_set._ip_feature_array
            
            bad_ip_prediction = fail_model.getClassifier().predict(ip_set._ip_feature_array)

            failList.extend([ip_set._ip_index[i] for i in range(0, len(bad_ip_prediction)) if bad_ip_prediction[i] == ip_set.BAD_TARGET])

        return failList
