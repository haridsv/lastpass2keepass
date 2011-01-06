# splashid2keepass
# Supports:
# Keepass XML - keepassxml
# USAGE: python splashid2keepass.py exportedCSVfile
# The SplashID Export format;
# Type,Custom 1,Custom 2,Custom 3,Custom 4,Custom 5,Custom 6,Custom 7,Custom 8,Custom 9,Date Modified,Notes,Category

import sys, csv, time, itertools, re # Toolkit
import codecs
import traceback
from datetime import datetime
import xml.etree as etree
import xml.etree.ElementTree as ET # Saves data, easier to type
from xml.etree.ElementTree import ElementTree as Orig_ElementTree # Saves data, easier to type

# Strings

fileError = "You either need more permissions or the file does not exist."
lineBreak = "____________________________________________________________\n"

treeName = "SplashID"

# Specific direct mappings.
genericFieldMap = {
    "group": 0,
    "title": 1,
    "notes": 11,
    "lastmodtime": 10,
}

# If a field is found here, then the field index specifies where to find it.
catSpecificFieldMap = {
    "Bank Accts": {
        "password": 3,
    },
    "Combinations": {
        "password": 2,
    },
    "Credit Cards": {
        "password": 5,
    },
    "Email Accts": {
        "username": 2,
        "password": 3,
    },
    "Identification": {
        "password": 2,
    },
    "Service Account": {
        "username": 4,
        "password": 5,
    },
    "Voice Mail": {
        "password": 3,
    },
    "Web Logins": {
        "username": 2,
        "password": 3,
        "url": 4,
    },
}

# If not found here, the field name would be "Custom <n>"
# These fields in addition to "Category" and any other custom fields are placed at the beginning of notes.
catSpecificDefFieldNames = {
    "Bank Accts": {
        2: "Account #",
        4: "Name",
        5: "Branch",
        6: "Phone #",
    },
    "Birthdays": {
        2: "Date",
    },
    "Calling Cards": {
        2: "Access #",
        3: "PIN",
    },
    "Clothes Size": {
        2: "Shirt Size",
        3: "Pant Size",
        4: "Shoe Size",
        5: "Dress Size",
    },
    "Credit Cards": {
        2: "Card #",
        3: "Expir Date",
        4: "Name",
        6: "Bank",
    },
    "Email Accts": {
        4: "POP3 Host",
        5: "SMTP Host",
    },
    "Emergency Info": {
        2: "Phone #",
    },
    "Frequent Flyer": {
        2: "Number",
        3: "Name",
        4: "Date",
    },
    "Identification": {
        3: "Name",
        4: "Date",
    },
    "Insurance": {
        2: "Policy #",
        3: "Group #",
        4: "Insured",
        5: "Date",
        6: "Phone #",
    },
    "Memberships": {
        2: "Acct #",
        3: "Name",
        4: "Date",
    },
    "Phone Numbers": {
        2: "Phone #",
    },
    "Prescriptions": {
        2: "Rx #",
        3: "Name",
        4: "Doctor",
        5: "Pharmacy",
        6: "Phone #",
    },
    "Serial Numbers": {
        2: "Serial #",
        3: "Date",
        4: "Reseller",
    },
    "Service Account": {
        2: "Name",
        3: "Account Number",
        6: "Web",
        7: "Phone",
    },
    "Vehicle Info": {
        2: "License #",
        3: "VIN #",
    },
    "Voice Mail": {
        2: "Access #",
    },
}


def formattedPrint(string):
    print lineBreak
    print string
    print lineBreak
       
# Files
# Check for existence/read/write.

def findField(category, fieldName):
    return ((category in catSpecificFieldMap and
             fieldName in catSpecificFieldMap[category]) and
            entry[catSpecificFieldMap[category][fieldName]] or
            "")

def CDATA(text=None):
    element = ET.Element(CDATA)
    element.text = text
    return element

class ElementTreeCDATA(Orig_ElementTree):
    def _write(self, file, node, encoding, namespaces):
        if node.tag is CDATA:
            # Quick HACK to get accented characters to decode correctly.
            text = node.text.decode("latin-1")
            text = u"\n<![CDATA[%s]]>\n" % text
            file.write(text)
        else:
            Orig_ElementTree._write(self, file, node, encoding, namespaces)

try:
    inputFile = sys.argv[1]
except:
    formattedPrint("USAGE: python splashid2keepass.py exportedTextFile")
    sys.exit()
    
try:
    f = open(inputFile, "r")
except IOError:
    traceback.print_exc()
    formattedPrint("Cannot read file: '%s' Error: '%s'" % (inputFile, fileError) )
    sys.exit()

# Create XML file.
outputFile = inputFile + ".export.xml"

try:
    w = codecs.open(outputFile, "w", "utf-8")
except IOError:
    traceback.print_exc()
    formattedPrint("Cannot write to disk... exiting. Error: '%s'" % (fileError) )
    sys.exit()

# Parser
# Parse w/ delimter being comma, and entries separted by newlines
reader = csv.reader(f, delimiter=',', quotechar='"')
headerLine = reader.next()
if not headerLine or len(headerLine) != 1 or headerLine[0] != 'SplashID Export File':
    raise Exception("File doesn't seem to be a SplashID export file")

# Create a list of the entries, we need to be able to index it later.
# Can't be done with reader object.
allEntries = []
for entry in reader:
    # This doesn't help for some reason, see the HACK above.
    #allEntries.append([x.decode("latin-1") for x in entry])
    allEntries.append(entry)

f.close() # Close the read file.

# Keepass XML generator
   
# Add doctype to head, clear file.
w.write('<?xml version="1.0" encoding="utf-8" standalone="yes"?>')

# Generate Creation date
# Form current time expression.
isoDtFormat = "%Y-%m-%dT%H:%M:%S"
sdDtFormat = "%B %d, %Y"
now = datetime.now()
formattedNow = now.strftime(isoDtFormat)

# Initialize tree
# build a tree structure
page = ET.Element('pwlist')
doc = ElementTreeCDATA(page)

# Dictionary of failed entries
failed = {}
    
formattedPrint("DEBUG of '%s' file conversion to the KeePassXML format, outputing to the '%s' file." %(inputFile,outputFile))
    
# A dictionary, organising the categories.
for entry in allEntries:
    try:
        # Each entryElement
        entryElement = ET.SubElement(page, "pwentry")
        # entryElement tree
        category = entry[genericFieldMap["group"]]
        ET.SubElement(entryElement, 'group', tree=treeName).text = category
        ET.SubElement(entryElement, 'title').text = entry[genericFieldMap["title"]]
        ET.SubElement(entryElement, 'username').text = findField(category, "username")
        ET.SubElement(entryElement, 'password').text = findField(category, "password")
        ET.SubElement(entryElement, 'url').text = findField(category, "url")
        ET.SubElement(entryElement, 'icon').text = "0"
        ET.SubElement(entryElement, 'creationtime').text = formattedNow
        try:
            lastModTime = datetime.strptime(entry[genericFieldMap["lastmodtime"]], sdDtFormat).strftime(isoDtFormat)
        except ValueError:
            lastModTime = formattedNow
        ET.SubElement(entryElement, 'lastmodtime').text = lastModTime
        ET.SubElement(entryElement, 'lastaccesstime').text = formattedNow
        ET.SubElement(entryElement, 'expiretime', expires="false").text = "2999-12-28T23:59:59"

        # Move the rest of the unused, non-empty fields into the notes field.
        usedFields = category in catSpecificFieldMap and catSpecificFieldMap[category].values() or []
        defFieldNames = category in catSpecificDefFieldNames and catSpecificDefFieldNames[category] or {}
        customFields = []
        # 9 custom fields.
        for i in xrange(1, 10):
            if i == 1 and category != 'Unfiled':
                continue
            if i not in usedFields:
                fieldName = i in defFieldNames and defFieldNames[i] or "Custom " + str(i)
                if entry[i]:
                    customFields.append("%s: %s" % (fieldName, entry[i]))
        if entry[genericFieldMap["notes"]]:
            if customFields:
                customFields.append("\n")
                customFields.append("Notes:")
            customFields.append(entry[genericFieldMap["notes"]].replace('\x0b', '\n'))
        notes = ET.SubElement(entryElement, 'notes')
        notes.append(CDATA("\n".join(customFields)))
    except Exception, e:
        # Catch illformed entries          
        # Grab entry position
        p = allEntries.index(entry) + 2
        failed[p] = [",".join(entry)]
        print "Failed to format entry at line %d, due to error: %s" % (p, ' '.join(e.args))

# Check if it was a clean conversion.
if len(failed) != 0:
    # Create a failed list.
    failedList = ["%d : %s" %(p, str(e[0]).decode("utf-8")) for p, e in failed.items()]
    formattedPrint("The conversion was not clean.")
    print "You need to manually import the below entries from the '%s' file, as listed by below." %(inputFile)
    formattedPrint("Line Number : entryElement")
    for x in failedList:
        print x

# Write out tree
# wrap it in an ElementTree instance, and save as XML
doc.write(w, encoding="utf-8")
w.close()

print lineBreak
print "\n'%s' has been succesfully converted to the KeePassXML format." %(inputFile)
print "Converted data can be found in the '%s' file.\n" %(outputFile)
print lineBreak
