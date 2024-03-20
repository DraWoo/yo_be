package com.yo.sm.service.board;

import com.yo.sm.model.dto.board.BoardDto;
import com.yo.sm.model.entity.board.Board;
import com.yo.sm.model.entity.member.Member;
import com.yo.sm.repository.board.BoardRepository;
import com.yo.sm.repository.member.MemberRepository;
import org.springframework.stereotype.Service;
import org.modelmapper.ModelMapper;

import javax.annotation.Resource;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class BoardService{

    @Resource
    private BoardRepository boardRepository;
    @Resource
    private ModelMapper modelMapper;
    @Resource
    private MemberRepository memberRepository; // MemberRepository 추가


    public BoardDto saveBoard(BoardDto boardDto) {
        // username을 이용하여 Member 엔티티를 조회합니다.
        Member member = memberRepository.findByUsername(boardDto.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        //board 엔티티 객체에 매핑 => 새로운 board 객체 생성
        //클라이언트에서 전달받은 데이터를 매핑하는데 사용
        Board board = modelMapper.map(boardDto, Board.class);
        board.setUser(member); // Member 설정
        board = boardRepository.save(board);
        return modelMapper.map(board, BoardDto.class);
    }

    public List<BoardDto> getAllBoards() {
        return boardRepository.findAll().stream()
                .map(board -> modelMapper.map(board, BoardDto.class))
                .collect(Collectors.toList());
    }

    public BoardDto getBoardById(Long id) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Board not found"));
        return modelMapper.map(board, BoardDto.class);
    }

    public BoardDto updateBoard(Long id, BoardDto boardDto) {
        Board existingBoard = boardRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Board not found"));
        modelMapper.map(boardDto, existingBoard);
        existingBoard = boardRepository.save(existingBoard);
        return modelMapper.map(existingBoard, BoardDto.class);
    }

    public void deleteBoard(Long id) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Board not found"));
        boardRepository.delete(board);
    }
}