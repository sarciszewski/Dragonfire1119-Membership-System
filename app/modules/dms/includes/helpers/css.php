<?php
/**************************************************************************
 * Dragonfire1119 Membership System AKA DMS
 * Copyright (C) 2012  Christopher Hicks
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 **************************************************************************/

class Css {
    
    function Css() {
        
    }
    
    function Cssself($css) {
        return "<style type=\"text/css\">$css</style>";
    }
    
    function cssurl($cssurl) {
        return "<link rel=\"stylesheet\" href=\"$cssurl\" type=\"text/css\" media=\"screen\" title=\"default\" />";
    }
}
/**
 * Initialize design object
 */
$css = new Css;
?>