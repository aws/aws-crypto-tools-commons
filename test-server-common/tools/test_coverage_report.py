"""Run with: python3 -m unittest discover -s test-server-common/tools"""

import tempfile
import unittest
from pathlib import Path

import coverage_report as report


class JacocoBranchesTest(unittest.TestCase):

    def test_covered_and_missed_branches_become_brda_records(self):
        root = Path(tempfile.mkdtemp())
        (root / "pkg").mkdir()
        (root / "pkg" / "A.java").write_text("")
        xml = root / "jacoco.xml"
        xml.write_text("""<report name="r"><package name="pkg"><sourcefile name="A.java">
<line nr="3" mi="0" ci="2" mb="1" cb="1"/>
<line nr="4" mi="2" ci="0" mb="2" cb="0"/>
<line nr="5" mi="0" ci="1" mb="0" cb="0"/>
</sourcefile></package></report>""")
        lcov = report.jacoco_xml_to_lcov(str(xml), [str(root)])
        self.assertEqual(["BRDA:3,0,0,1", "BRDA:3,0,1,0", "BRDA:4,0,0,-", "BRDA:4,0,1,-"],
                         [line for line in lcov.splitlines() if line.startswith("BRDA:")])


class CoberturaBranchesTest(unittest.TestCase):

    def test_condition_coverage_becomes_brda_records(self):
        xml = Path(tempfile.mkdtemp()) / "cobertura.xml"
        xml.write_text("""<coverage><sources><source>/src</source></sources><packages><package><classes>
<class filename="/src/A.cs"><lines>
<line number="3" hits="1" branch="True" condition-coverage="50% (1/2)"/>
<line number="4" hits="0" branch="True" condition-coverage="0% (0/2)"/>
<line number="5" hits="1" branch="False"/>
</lines></class>
</classes></package></packages></coverage>""")
        lcov = report.cobertura_to_lcov(str(xml))
        self.assertEqual(["BRDA:3,0,0,1", "BRDA:3,0,1,0", "BRDA:4,0,0,-", "BRDA:4,0,1,-"],
                         [line for line in lcov.splitlines() if line.startswith("BRDA:")])


if __name__ == "__main__":
    unittest.main()
