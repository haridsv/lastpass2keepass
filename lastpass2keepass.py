# LastPassConvertor
#TODO
# Add nested group support.

# Supports:
# Keepass XML - keepassxml
#
# USAGE: python lastpassconvertor.py exportedTextFile
#
# The LastPass Export format;
# url,username,password,1extra,name,grouping(\ delimited),last_touch,launch_count,fav

import sys, csv, time, datetime, itertools, re
from lxml import etree

# Strings

fileError = "You either need more permissions or the file does not exist."
lineBreak = "____________________________________________________________\n"

def formattedPrint(string):
    print lineBreak
    print string
    print lineBreak
    
# Files
try:
    inputFile = sys.argv[1]
except:
    formattedPrint("USAGE: python lastpassconvertor.py exportedTextFile")
    sys.exit()
    
outputFile = "export.xml"

# Check if we can read.

try:
    f = open(inputFile)
except IOError:
    formattedPrint("Cannot read file: '%s'" %(inputFile), fileError)
    sys.exit()

# Create a csv dialect and extract the data to a reader object.
dialect = csv.Sniffer().sniff(f.read(1024))
f.seek(0)
reader = csv.reader(f, dialect)

# Create a list of the entries, allow us to manipulate it.
# Can't be done with reader object.

allEntries = []

for x in reader:
    allEntries.append(x)
allEntries.pop(0) # Remove LP format string.

f.close() # Close the read file.

# Keepass XML generator

# Create XML file.
try:
    open(outputFile, "w").close() # Clean.
    w = open(outputFile, "aw")
except IOError:
    formattedPrint("Cannot write to disk... exiting.", fileError)
    sys.exit()
    
# Add doctype.
w.write("<!DOCTYPE KEEPASSX_DATABASE>")

# Generate Creation date
now = datetime.datetime.now()

# Form current time expression.
formattedNow = now.strftime("%Y-%m-%dT%H:%M")

# Initialize tree
page = etree.Element('database')
doc = etree.ElementTree(page)

# List of failed entries
failed = {}
    
formattedPrint("DEBUG of '%s' file conversion to the KeePassXML format, outputing to the '%s' file." %(inputFile,outputFile))
    
# A dictionary, organising the categories.
resultant = {}
    
# Parses allEntries into a resultant.
for li in allEntries:
    try:
        categories = re.split(r"[/\\]",li[5]) # Grab final category.
        for x in categories:
            resultant.setdefault(categories.pop(), []).append(li) # Sort by categories.
    except:
        # Catch illformed entries         
        # Grab entry position
        p = allEntries.index(li) + 2
        failed[p] = [",".join(li)]
        print "Failed to format entry at line %d" %(p)

# Initilize and loop through all entries
for x, v in resultant.iteritems():
    headElt = etree.SubElement(page, 'group')
    etree.SubElement(headElt, 'title').text = str(x)
    etree.SubElement(headElt, 'icon').text = "0"
    
    for entry in v: 
    # Entry information
        try:
            # Each Entry
            entryElt = etree.SubElement(headElt, 'entry')
            etree.SubElement(entryElt, 'title').text = str(entry[4])
            etree.SubElement(entryElt, 'username').text = str(entry[1])
            etree.SubElement(entryElt, 'password').text = str(entry[2])
            etree.SubElement(entryElt, 'url').text = str(entry[0])
            etree.SubElement(entryElt, 'comment').text = str(entry[3])
            etree.SubElement(entryElt, 'icon').text = "0"
            etree.SubElement(entryElt, 'creation').text = formattedNow
            etree.SubElement(entryElt, 'lastaccess').text = str(entry[6])
            etree.SubElement(entryElt, 'lastmod').text = str(entry[7])
            etree.SubElement(entryElt, 'expire').text = "Never"
        except:
            # Catch illformed entries          
            # Grab entry position
            p = allEntries.index(entry) + 2
            failed[p] = [",".join(entry)]
            print "Failed to format entry at line %d" %(p)

# Check if it was a clean conversion.
if len(failed) != 0:
    # Create a failed list.
    failedList = ["%d : %s" %(p, str(e[0]).decode("utf-8")) for p, e in failed.items()]
    formattedPrint("The conversion was not clean.")
    print "You need to manually import the below entries from the '%s' file, as listed by below." %(inputFile)
    formattedPrint("Line Number : Entry")
    for x in failedList:
        print x

# Write out tree
doc.write(w)
w.close()

print lineBreak
print "\n'%s' has been succesfully converted to the KeePassXML format." %(inputFile)
print "Converted data can be found in the '%s' file.\n" %(outputFile)
print lineBreak
