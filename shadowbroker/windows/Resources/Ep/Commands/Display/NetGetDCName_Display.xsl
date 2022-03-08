<?xml version='1.0' ?>
<xsl:transform xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 <xsl:import href="StandardTransforms.xsl"/>
 <xsl:output method="text"/>

 <xsl:template match="DomainController">

   <xsl:text>Domain Controller : </xsl:text>
   <xsl:value-of select="."/>
   <xsl:call-template name="PrintReturn"/>

 </xsl:template>

</xsl:transform>