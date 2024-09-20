/* Copyright (c) 2024, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is designed to work with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have either included with
   the program or referenced in the documentation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <gtest/gtest.h>

#include "fts0fts.h"
#include "fts0types.h"
#include "univ.i"
#include "ut0rbt.h"

namespace innodb_ut0rbt_unittest {

/* Doc id array for testing with values exceeding 32-bit integer limit */
const doc_id_t doc_ids[] = {
    17574ULL,      89783ULL,      94755ULL,      97537ULL,      101358ULL,
    101361ULL,     102587ULL,     103571ULL,     104018ULL,     106821ULL,
    108647ULL,     109352ULL,     109379ULL,     110325ULL,     122868ULL,
    210682130ULL,  231275441ULL,  234172769ULL,  366236849ULL,  526467159ULL,
    1675241735ULL, 1675243405ULL, 1947751899ULL, 1949940363ULL, 2033691953ULL,
    2148227299ULL, 2256289791ULL, 2294223591ULL, 2367501260ULL, 2792700091ULL,
    2792701220ULL, 2817121627ULL, 2820680352ULL, 2821165664ULL, 3253312130ULL,
    3404918378ULL, 3532599429ULL, 3538712078ULL, 3539373037ULL, 3546479309ULL,
    3566641838ULL, 3580209634ULL, 3580871267ULL, 3693930556ULL, 3693932734ULL,
    3693932983ULL, 3781949558ULL, 3839877411ULL, 3930968983ULL, 4146309172ULL,
    4524715523ULL, 4524715525ULL, 4534911119ULL, 4597818456ULL};

const doc_id_t search_doc_id = 1675241735;

namespace {
struct dummy {
  doc_id_t doc_id;
};
}  // namespace

TEST(ut0rbt, fts_doc_id_cmp) {
  ib_rbt_t *doc_id_rbt = rbt_create(sizeof(dummy), fts_doc_id_field_cmp<dummy>);

  /* Insert doc ids into rbtree. */
  for (unsigned i = 0; i < sizeof(doc_ids)/sizeof(doc_ids[0]); i++)
  {
    const doc_id_t& doc_id = doc_ids[i];
    ib_rbt_bound_t parent;
    dummy obj;
    obj.doc_id = doc_id;

    if (rbt_search(doc_id_rbt, &parent, &obj.doc_id) != 0) {
      rbt_add_node(doc_id_rbt, &parent, &obj);
    }
  }

  /* Check if doc id exists in rbtree */
  ib_rbt_bound_t parent;
  EXPECT_EQ(rbt_search(doc_id_rbt, &parent, &search_doc_id), 0);

  rbt_free(doc_id_rbt);
}
}  // namespace innodb_ut0rbt_unittest
