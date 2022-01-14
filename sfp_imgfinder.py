# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_imgFinder
# Purpose:      Identify jar links and information
#
# Author:      Marta Berges <marticsplace@gmail.com>
#
# Created:     11/01/2022
# Copyright:   (c) Marta Berges 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

import subprocess
from bs4 import BeautifulSoup
from mechanize import Browser
import mechanize
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_imgFinder(SpiderFootPlugin):
    meta = {
        'name': "imgFinder",
        'summary': "Perform a file finder",
        'flags': ["IMG", "FINDER",],
        'useCases': ["EDUCATION", "JAR"],
        'categories': ["FINDER"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    #         return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT", "INTERESTING_FILE",
    #                 "JUNK_FILE", "LINKED_URL_EXTERNAL", "LINKED_URL_INTERNAL", "PROVIDER_TELCO",
    #                 "SSL_CERTIFICATED_EXPIRED", "TCP_PORT_OPEN", "URL_JAVA_APPLET", "URL_JAVA_APPLET_HISTORIC",
    #                 "VULNERABILITY_GENERAL", "SIMILARDOMAIN"]
    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERESTING_FILE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DOMAIN_NAME", "INTERESTING_FILE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")
            print(f"Received event, {eventName}, from {srcModuleName}")
            print("Eventipe:", event.eventType, "\nEVENTMODULE :", event.module, "\nEVENTDATA :", event.data)

            self.sf.debug(f"We use the data: {eventData}")

            ########################
            # Insert here the code #
            ########################
            print(f"We use the data: {eventData}")
            data = subprocess.run('sublist3r -d ' + eventData, shell=True, capture_output=True, text=True)
            output = str(data.stdout)
            print("OUTPUT: ", output.format())
            allDomain = output.split('\n')
            domains = list()
            for dom in allDomain:
                if eventData in dom:
                    res = dom[5:-4]
                    domains.append(res)
            #Quitamos la primera aparicion
            domains.pop(0)
            # Empieza módulo
            # se pueden añadir más archivos o partes a extraer del html, dejo el array con un elemento.
            tipoArchivos = ['img']
            info = []
            for found in domains:
                print("DOM :", found)
                for tipoArchivo in tipoArchivos:
                    info = self.buscadorArchivos(found, tipoArchivo)

                evt = SpiderFootEvent("DOMAIN_NAME", found, self.__name__, event)
                self.notifyListeners(evt)

            for trozo in info:
                evt = SpiderFootEvent("INTERESTING_FILE", trozo, self.__name__, event)
                self.notifyListeners(evt)

            if not data:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return

        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return


    def buscadorArchivos(self, url, tipoArchivo):


        print("Abriendo el navegador", "https://"+url)
        # Abrir URL
        try:
            response = mechanize.urlopen("https://"+url)
            print("hay respuesta")
        except Exception as e:
            self.sf.error("Error al tratar la url: " + url + ": " + str(e))
            return
        #print("obtenemos respuesta", response.head())
        #leer la respuesta
        html = response.read()
        print("Lee la respuesta\n")

        # llamada a soup para extraer datos
        soup = BeautifulSoup(html, features="html.parser")
        datos = []
        #print("llamada a soup: OK", print(soup))
        #Para cada referencia encontrada
        try:
            for link in soup.find_all(tipoArchivo):
                print("EL LINK", link.get('src'))
                info = link.get('src')
                # En algunos casos, data lazy src contiene la ruta
                if "data" in info:
                    info = link.get('data_lazy_src')
                datos.append(info)
                print("INFO : ", info)
        except Exception as e:
            self.sf.error("Ha fallado tratando la url " + url + ": " + str(e))
            return
        return datos

print("END OF JARJARLIVES")
# End of sfp_new_module class
