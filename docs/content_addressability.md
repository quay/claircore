# Content-Addressability
ClairCore treats both image hashes and layer hashes as content addressable.  
Manifests MUST provide a content addressable hash uniquely identifying the image as a whole.  
Layers MUST provide a content addressable hash unique identifying the layer's contents.  

# Reducing work
ClairCore will use content addressable hashes to understand what work it needs to perform.  
If ClairCore comes across a image or layer hash which has been scanned by all configured scanners it will retrieve the existing results and not perform work.  
If ClairCore is started with a new set of package scanners and encounters a previously seen image or layer hash it will rescan the image or layer.  
ClairCore will only perform a scan with the missing scanner on the incoming image or layers.  
