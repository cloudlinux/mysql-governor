/*
 * Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
 *
 * Licensed under CLOUD LINUX LICENSE AGREEMENT
 * http://cloudlinux.com/docs/LICENSE.TXT
 *
 * Author: Igor Seletskiy <iseletsk@cloudlinux.com>, Alexey Berezhok <alexey.berezhok@cloudlinux.com>
 */

#ifndef XML_H_
#define XML_H_

#define MAX_XML_PATH 4096

typedef struct __xml_data
{
	void *doc;
	void *root;
	char path[MAX_XML_PATH];
} xml_data;

xml_data *parseConfigData(const char *path, char *error, int maxErrDescr);
void *FindElementWithName(xml_data *data, void *node, const char *nodeName);
const char *getElemAttr(void *node, const char *attrName);
const char *getElemValue(void *node);
void releaseElemValue(const char *value);
void *setNode(xml_data *data, void *node, const char *nodeName,
		const char *value);
void *setAttr(void *node, const char *attrName,
		const char *value);
int saveXML(xml_data * data, char *path);
void releaseConfigData(xml_data *data);
void *getNextChild(void *node, const char *childName, void *prev_node);
void removeNode(void *node);
void *getNextAttr(void *nodeValue, void *prev_attr);
char *getAttributeName(const void *pAttr);
char *getAttributeValue(const void *pAttr);
void *FindElementWithNameAndAttr(xml_data *data, void *node, const char *nodeName,
		const char *attrName, const char *attrValue);
void *setNodeWithAttr(xml_data *data, void *node, const char *nodeName,
		const char *value, const char *attrName, const char *attrValue);

#endif /* XML_H_ */
