# PFG-NDNMacaroons
===================

Instrucciones de instalación

###Prerequisitos

Esta implementación ha sido probada sobre Ubuntu 16.04.

Requerido:

* [ndn-cxx y sus dependencias](http://named-data.net/doc/ndn-cxx/0.4.1/INSTALL.html)
 [repositorio ndn-cxx 0.4.1](https://github.com/named-data/ndn-cxx/releases/tag/ndn-cxx-0.4.1)
* [Networking Forwarding Daemon(NFD)](http://named-data.net/doc/NFD/0.4.1/INSTALL.html)
 [repositorio NFD 0.4.1](https://github.com/named-data/NFD/releases/tag/NFD-0.4.1)
* Boost libraries
* [libmacaroons](https://github.com/rescrv/libmacaroons)
* [protobuf](https://github.com/google/protobuf)

###Construcción

Para construir la librería `PFG-NDNMacaroons` hay que ejecutar
los comandos en el siguiente orden dentro del directorio
`PFG-NDNMacaroons/`:

	cd libNDNMacaroon
	./waf configure
	./waf
	sudo ./waf install
	sudo ldconfig

Para construir el ejemplo del sistema de delegación de permisos
para acceder a recursos, hay que ejecutar los siguientes comandos
en el directorio `PFG-NDNMacaroons/`:

	./waf configure
	./waf

###Ejecutar el ejemplo

Existen 4 programas principales:

   - *Producer*: publica los datos cifrados y las claves de datos tambien cifradas.
   - *Access Controller*: provee del Macaroon necesario para acceder a la clave de grupo y poder descifrar los datos.
   - *Group Keys Distributor*: provee del Discharge Macaroon con la clave de grupo.
   - *Consumer1*: solicita los datos cifrados y la clave de datos cifrada a Producer.
				Solicita el Macaroon a Access Controller para acceder a la clave de grupo necesaria para descifrar la clave de datos.
				Utiliza el Macaroon para obtener el Discharge Macaroon con la clave de grupo.
				Descifra los datos con la clave de grupo obtenida.

Antes de ejecutar el ejemplo es necesario crear las claves DSK y KSK utilizadas por las entidades ya nombradas. Para crear las claves KSK/DSK ejecute el script desde el directorio `PFG-NDNMacaroon/`:

	./keys.sh

Ejecutar cada programa en un terminal diferente en el siguiente orden, desde el directorio `PFG-NDNMacaroons/`:

	1)Producer:			./build/bin/producer/producer
	2)Group Keys Distributor:	./build/bin/group-keys-distributor/group-keys-distributor
	3)Access Controller:		./build/bin/access-controller/access-controller
	4)Consumer1:			./build/bin/consumer1/consumer1
