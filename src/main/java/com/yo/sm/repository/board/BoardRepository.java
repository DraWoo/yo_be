package com.yo.sm.repository.board;

import com.yo.sm.model.entity.board.Board;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
/**
 * JpaRepository를 상속받아, 기본적인 CRUD(Create, Read, Update, Delete) 작업과 페이징, 정렬 등의 기능을 제공
 * */
@Repository
public interface BoardRepository extends JpaRepository<Board, Long> {

}
